package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/cookiejar"

	"github.com/yhat/scrape"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func redirectPolicyFunc(req *http.Request, via []*http.Request) error{
	req.Header.Add("Authorization","Basic "+basicAuth("username1","password123"))
	return nil
}



func main() {

	cookieJar, _ := cookiejar.New(nil)

	client := &http.Client{
		Jar: cookieJar,
		CheckRedirect: redirectPolicyFunc,
	}

	req, err := http.NewRequest("GET", "https://news.ycombinator.com/", nil)
	req.SetBasicAuth("username1", "password123")

	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)

	root, err := html.Parse(resp.Body)
	if err != nil {
		panic(err)
	}

	// define a matcher
	matcher := func(n *html.Node) bool {
		// must check for nil values
		if n.DataAtom == atom.A && n.Parent != nil && n.Parent.Parent != nil {
			return scrape.Attr(n.Parent.Parent, "class") == "athing"
		}
		return false
	}
	// grab all articles and print them
	articles := scrape.FindAll(root, matcher)
	for i, article := range articles {
		fmt.Printf("%2d %s (%s)\n", i, scrape.Text(article), scrape.Attr(article, "href"))
	}
}
