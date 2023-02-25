package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gocarina/gocsv"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

type InputMetadataRow struct {
	BatesNumber string `csv:"bates_number"`
	FileName    string `csv:"filename"`
}

type OutputMetadataRow struct {
	ParentBatesNumber string    `csv:"parent_bates_number"`
	DocId             string    `csv:"document_id"`
	DocTitle          string    `csv:"document_title"`
	CreatedAt         time.Time `csv:"created_at"`
}

type ExtractedURL struct {
	e   Extractor
	url string
}

type DocumentMetadata struct {
	Title     string
	CreatedAt time.Time
}

type Extractor interface {
	Extract(data []byte) []string
	FetchDocument(url string) (io.ReadCloser, DocumentMetadata)
}

type GoogleDocExtractor struct {
	service *drive.Service
}

func NewGoogleDocExtractor(ctx context.Context) (*GoogleDocExtractor, error) {
	// TODO: parameterize
	b, err := os.ReadFile("credentials.json")
	if err != nil {
		return nil, fmt.Errorf("Error opening Google Docs credentials.json: %w", err)
	}

	config, err := google.ConfigFromJSON(b, drive.DriveReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("Error creating Google API config: %w", err)
	}

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the 'code' of the URL you're redirected to: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		return nil, fmt.Errorf("Unable to read authorization code: %w", err)
	}

	tok, err := config.Exchange(ctx, authCode)
	if err != nil {
		return nil, fmt.Errorf("Unable to retrive Google Docs API token: %w", err)
	}

	client := config.Client(ctx, tok)

	service, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("Error creating Google Docs client: %w", err)
	}

	return &GoogleDocExtractor{
		service: service,
	}, nil
}

var googleDocsRegexp = regexp.MustCompile(`https://docs.google.com/document/d/([\w\d_]+)`)

func (g *GoogleDocExtractor) Extract(data []byte) []string {
	results := googleDocsRegexp.FindAll(data, -1)
	stringResults := []string{}
	for _, r := range results {
		stringResults = append(stringResults, string(r))
	}
	return stringResults
}

func (g *GoogleDocExtractor) FetchDocument(url string) (io.ReadCloser, DocumentMetadata) {
	docId := googleDocsRegexp.FindStringSubmatch(url)[1]
	doc, err := g.service.Files.Get(docId).Do()
	if err != nil {
		// TODO
		panic(err)
	}

	docBody, err := g.service.Files.Export(docId, "application/pdf").Download()

	return docBody.Body, DocumentMetadata{
		Title: doc.Name,
	}
}

func extractMimeBody(data []byte) []byte {
	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		// TODO
		panic(err)
	}
	mediaType, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil {
		// TODO
		panic(err)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		body, err := ioutil.ReadAll(m.Body)
		if err != nil {
			// TODO
			panic(err)
		}
		return body
	}

	reader := multipart.NewReader(m.Body, params["boundary"])
	if reader == nil {
		// TODO
		panic("XXX?")
	}

	body := []byte{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			// TODO
			panic(err)
		}
		partBody, err := ioutil.ReadAll(part)
		if err != nil {
			// TODO
			panic(err)
		}
		body = append(body, partBody...)
	}
	return body
}

func appendIfNotPresent(els []string, v string) []string {
	for _, el := range els {
		if v == el {
			return els
		}
	}
	return append(els, v)
}

func run(ctx *cli.Context) error {
	f, err := os.Open(ctx.String("metadata"))
	if err != nil {
		return fmt.Errorf("Error opening metadata file: %w", err)
	}
	defer f.Close()

	metadataRows := []InputMetadataRow{}
	if err := gocsv.UnmarshalFile(f, &metadataRows); err != nil {
		return fmt.Errorf("Error reading metadata CSV: %w", err)
	}
	log.WithFields(log.Fields{
		"num_rows": len(metadataRows),
		"path":     f.Name(),
	}).Info("Loaded metadata file")

	googleDocs, err := NewGoogleDocExtractor(ctx.Context)
	if err != nil {
		return fmt.Errorf("Error creating Google Docs extractor: %w", err)
	}
	extractors := []Extractor{googleDocs}

	// {extractedURL: [slice of bates numbers]}
	relevantUrls := make(map[ExtractedURL][]string)
	emailFS := os.DirFS(ctx.String("email-folder"))
	for _, row := range metadataRows {
		log.WithFields(log.Fields{"bates_number": row.BatesNumber}).Info("Parsing email")
		data, err := fs.ReadFile(emailFS, row.FileName)
		if err != nil {
			return fmt.Errorf("Error reading file email file: %w", err)
		}

		mimeBody := extractMimeBody(data)

		for _, extractor := range extractors {
			for _, url := range extractor.Extract(mimeBody) {
				extractedUrl := ExtractedURL{e: extractor, url: url}
				val, ok := relevantUrls[extractedUrl]
				if !ok {
					val = []string{}
				}
				log.WithFields(log.Fields{"bates_number": row.BatesNumber, "url": url, "new": !ok}).Info("Extracted URL")
				relevantUrls[extractedUrl] = appendIfNotPresent(val, row.BatesNumber)
			}
		}
	}
	log.WithFields(log.Fields{"num_urls": len(relevantUrls)}).Info("Parsed email files")

	outputRows := []OutputMetadataRow{}
	for extractedUrl, batesNumbers := range relevantUrls {
		docId := uuid.New()
		doc, metadata := extractedUrl.e.FetchDocument(extractedUrl.url)
		defer doc.Close()
		f, err := os.Create(path.Join(ctx.String("output-folder"), docId.String()+".pdf"))
		if err != nil {
			// TODO
			panic(err)
		}
		defer f.Close()
		_, err = io.Copy(f, doc)
		if err != nil {
			// TODO
			panic(err)
		}
		for _, batesNumber := range batesNumbers {
			outputRows = append(outputRows, OutputMetadataRow{
				ParentBatesNumber: batesNumber,
				DocId:             docId.String(),
				DocTitle:          metadata.Title,
				CreatedAt:         metadata.CreatedAt,
			})
		}
	}

	f, err = os.Create(ctx.String("output-metadata"))
	if err != nil {
		// TODO
		panic(err)
	}
	defer f.Close()
	err = gocsv.MarshalFile(&outputRows, f)
	if err != nil {
		return fmt.Errorf("Error creating output CSV: %w", err)
	}

	log.Info("Done")
	return nil
}

func main() {
	app := &cli.App{
		Name: "doc-extractor",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "metadata",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "email-folder",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output-metadata",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output-folder",
				Required: true,
			},
		},
		Action: run,
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
