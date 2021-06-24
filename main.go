package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"io"
	"net/http/httputil"
	"net/url"

	"github.com/NotInTheSubject/prowler"
	"github.com/sirupsen/logrus"
	// mods "github.com/NotInTheSubject/crips/pkg/modifiers"
)

// https://www.google.com/imghp#
// access_token=AQAAAABVeLR8AAcrNJxQV_sR8kbIv9OtUCTzZ_4&token_type=bearer&expires_in=31536000

// type sequence = []mods.RequestProducer

func Requests() {
	req, err := NewRequestProvider().CreateFolder("/raw", []string{})
	if err != nil {
		logrus.Fatalf("Request-CreatingRequest: \n%+v", err)
	}
	bytesReq, err := httputil.DumpRequest(req, true)
	if err != nil {
		logrus.Fatalf("Request-DumpRequest: \n%+v", err)
	}
	logrus.Infof("Request: \n%+v", string(bytesReq))
	client := &http.Client{
		Timeout: time.Second * 30,
	}
	res, err := client.Do(req)
	if err != nil {
		logrus.Fatalf("Request-Do: %+v", err)
	}
	bytesRes, err := httputil.DumpResponse(res, true)
	if err != nil {
		logrus.Fatalf("Request-DumpResponse: %+v", err)
	}
	logrus.Infof("Response: \n%+v", string(bytesRes))
	logrus.Info("Success")
}

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

func (s sequenceProducer) GetRequest(resp *http.Response) (prowler.IdentifiedRequest, error) {
	waiting := func() {<- time.After(5 * time.Second)}

	if resp != nil {
		if resp.StatusCode == 409 {
			waiting()
			s.progress--
		} else if resp.StatusCode > 400 {
			return prowler.IdentifiedRequest{}, fmt.Errorf("unexpected status code (%v) in the response", resp.StatusCode)
		}
	}
	defer func() { s.progress++ }()

	if s.progress == 0 {
		req, err := s.rp.CreateFolder(s.folderName, []string{})
		return prowler.IdentifiedRequest{Request: req, Identifer: "creating folder"}, err
	}
	if s.progress == 1 {
		destination := s.folderName + "newdest"
		req, err := s.rp.MoveResource(s.folderName, destination, []string{})
		s.folderName = destination
		return prowler.IdentifiedRequest{Request: req, Identifer: "moving folder"}, err
	}
	if s.progress == 2 {
		req, err := s.rp.DeleteFolder(s.folderName, []string{})
		return prowler.IdentifiedRequest{Request: req, Identifer: "deleting folder"}, err
	}
	return prowler.IdentifiedRequest{}, fmt.Errorf("sequence is finished")
}

type requestSystem struct{}

func (rs requestSystem) GetSequenceProducer() (prowler.SequenceProducer, error) {
	folderName := fmt.Sprintf("/fuzztest%v", rand.Int())
	return sequenceProducer{progress: 0, folderName: folderName, rp: NewRequestProvider()}, nil
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
