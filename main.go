package main

import (
	"fmt"
	"net/http"
	"time"

	"io"
	"net/url"

	"github.com/NotInTheSubject/prowler"
	"github.com/sirupsen/logrus"
	"github.com/satori/go.uuid"
)

// access_token=AQAAAABVeLR8AAcrNJxQV_sR8kbIv9OtUCTzZ_4&token_type=bearer&expires_in=31536000

type ApiRequestProvider struct {
	startURL url.URL
}

func NewRequestProvider() ApiRequestProvider {
	URL, err := url.Parse("https://cloud-api.yandex.net/v1/disk/resources")
	if err != nil {
		logrus.Fatal(err)
	}
	var res = ApiRequestProvider{
		startURL: *URL,
	}
	return res
}

func (rp ApiRequestProvider) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "OAuth AQAAAABVeLR8AAcrNJxQV_sR8kbIv9OtUCTzZ_4")
	return req, nil
}

func (rp ApiRequestProvider) CreateFolder(path string, fields []string) (*http.Request, error) {
	values := url.Values{}

	values.Add("path", path)
	for _, v := range fields {
		values.Add("fields", v)
	}

	rp.startURL.RawQuery = values.Encode()

	req, err := rp.newRequest("PUT", rp.startURL.String(), nil)
	if err != nil {
		return req, fmt.Errorf("CreateFolder: %+v", err)
	}
	return req, nil
}

func (rp ApiRequestProvider) DeleteFolder(path string, fields []string) (*http.Request, error) {
	values := url.Values{}

	values.Add("path", path)
	for _, v := range fields {
		values.Add("fields", v)
	}

	rp.startURL.RawQuery = values.Encode()

	req, err := rp.newRequest("DELETE", rp.startURL.String(), nil)
	if err != nil {
		return req, fmt.Errorf("DeleteFolder: %+v", err)
	}
	return req, nil
}

func (rp ApiRequestProvider) MoveResource(from, path string, fields []string) (*http.Request, error) {
	values := url.Values{}

	values.Add("from", from)
	values.Add("path", path)

	for _, v := range fields {
		values.Add("fields", v)
	}

	rp.startURL.RawQuery = values.Encode()

	req, err := rp.newRequest("POST", rp.startURL.String(), nil)
	if err != nil {
		return req, fmt.Errorf("MoveResource: %+v", err)
	}
	return req, nil
}

type sequenceProducer struct {
	progress   int
	folderName string
	rp         ApiRequestProvider
}

type wrapperSeqProd struct {
	s *sequenceProducer
}

func (w wrapperSeqProd) GetRequest(resp *http.Response) (prowler.IdentifiedRequest, error) {
	return w.s.GetRequest(resp)
}

func (s *sequenceProducer) GetRequest(resp *http.Response) (prowler.IdentifiedRequest, error) {
	// waiting := func() { <-time.After(5 * time.Second) }

	if resp != nil {

		logrus.
			WithField("resp-code", resp.StatusCode).
			WithField("progress", s.progress).Info()

		if resp.StatusCode > 400 {
			return prowler.IdentifiedRequest{}, fmt.Errorf("unexpected status code (%v) in the response", resp.StatusCode)
		} else {
			s.progress++
		}
	}

	if s.progress == 0 {
		req, err := s.rp.CreateFolder(s.folderName, []string{})
		return prowler.IdentifiedRequest{Request: req, Identifer: "creating folder"}, err
	}
	if s.progress == 1 {
		req, err := s.rp.DeleteFolder(s.folderName, []string{})
		return prowler.IdentifiedRequest{Request: req, Identifer: "deleting folder"}, err
	}
	return prowler.IdentifiedRequest{}, fmt.Errorf("sequence is finished")
}

type requestSystem struct{}

func (rs requestSystem) GetSequenceProducer() (prowler.SequenceProducer, error) {
	
	folderName := fmt.Sprintf("/fuzz-testfolder-%v", uuid.NewV4().String())
	return wrapperSeqProd{&sequenceProducer{
		progress:   0,
		folderName: folderName,
		rp:         NewRequestProvider(),
	}}, nil
}

func main() {
	var (
		es            prowler.ExternalSystem = requestSystem{}
		stopCondition prowler.StopCondition  = func(fs prowler.FuzzingStatistic) bool {
			return fs.SequenceExecutedTimes > 100
		}
	)
	prowler.RunProwling(logrus.New(), es, http.Client{Timeout: time.Minute / 2}, prowler.DefaultModifiers(), stopCondition)
	fmt.Println("done")
}
