package mcp

import (
	"bufio"
	"context"
	"io"
	"net/http"
)

// ServeStdio runs the MCP protocol over newline-delimited JSON-RPC (the stdio
// transport used by Claude Code / opencode).
func (s *Server) ServeStdio(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	reader := bufio.NewReaderSize(stdin, 1<<20)
	writer := bufio.NewWriter(stdout)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if resp := s.Handle(trimNL(line)); resp != nil {
				if _, werr := writer.Write(append(resp, '\n')); werr != nil {
					return werr
				}
				if ferr := writer.Flush(); ferr != nil {
					return ferr
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// ServeHTTP answers a single JSON-RPC request (the HTTP MCP transport).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	resp := s.Handle(trimNL(body))
	if resp == nil {
		resp = []byte("{}")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func trimNL(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b
}
