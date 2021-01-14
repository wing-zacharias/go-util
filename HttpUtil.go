package util

import (
	"bytes"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"time"
)

type HttpClient struct {
	client *http.Client
}

type HttpRequest struct {
	request *http.Request
}

func NewHttpClient() *HttpClient {
	httpClient := &HttpClient{
		client: &http.Client{},
	}
	return httpClient
}

func MakeRequest(method, url string, data []byte) (*HttpRequest, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	hr := &HttpRequest{
		request: req,
	}
	return hr, nil
}

func (h *HttpRequest) SetHeaders(headers map[string]string) error {
	if h.request != nil {
		for k, v := range headers {
			h.request.Header.Add(k, v)
		}
		return nil
	}
	return errors.Errorf("request is null! ")
}

func (h *HttpRequest) SetBasicAuth(username string, password string) error {
	if h.request != nil {
		h.request.SetBasicAuth(username, password)
		return nil
	}
	return errors.Errorf("request is null! ")
}

func (h *HttpRequest) SetCookies(c *http.Cookie) error {
	if h.request != nil {
		h.request.AddCookie(c)
		return nil
	}
	return errors.Errorf("request is null! ")
}

func (h *HttpClient) SetTimeout(timeout time.Duration) {
	h.client.Timeout = timeout
}

func (h *HttpClient) SetTransport(transport *http.Transport) {
	h.client.Transport = transport
}

func (h *HttpClient) DoRequest(request *HttpRequest) ([]byte, error) {
	var err error
	resp, err := h.client.Do(request.request)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		bRes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return bRes, nil
	}
	return nil, errors.Errorf("response code:%v", resp.StatusCode)
}
