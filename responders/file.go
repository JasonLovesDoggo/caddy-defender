package responders

import (
    "bytes"
    "net/http"
    "os"
    "sync"
    "time"
    "io/ioutil"
)

// FileResponder responds with a file and allows the user to specify headers.
type FileResponder struct {
    FilePath string
    Headers  map[string]string
    content  []byte
    modTime  time.Time
    once     sync.Once
}

// loadFile loads the file content into memory
func (f *FileResponder) loadFile() error {
    file, err := os.Open(f.FilePath)
    if err != nil {
        return err
    }
    defer file.Close()

    fileInfo, err := file.Stat()
    if err != nil {
        return err
    }

    f.content, err = ioutil.ReadAll(file)
    if err != nil {
        return err
    }

    f.modTime = fileInfo.ModTime()
    return nil
}

func (f *FileResponder) Respond(w http.ResponseWriter, r *http.Request) error {
    var err error
    f.once.Do(func() {
        err = f.loadFile()
    })
    if err != nil {
        http.Error(w, "File not found", http.StatusNotFound)
        return err
    }

    for key, value := range f.Headers {
        w.Header().Set(key, value)
    }

    http.ServeContent(w, r, f.FilePath, f.modTime, bytes.NewReader(f.content))
    return nil
}
