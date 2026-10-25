package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func scanDirectory(path, output string, rules []rule) ([]Finding, []SecretFinding, int, error) {
	root, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, 0, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, nil, 0, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, 0, fmt.Errorf("-d must name a real directory, not a symlink")
	}
	var excluded os.FileInfo
	if output != "" {
		excluded, err = os.Stat(output)
		if err != nil && !os.IsNotExist(err) {
			return nil, nil, 0, err
		}
	}
	var files []inputFile
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || excluded != nil && os.SameFile(info, excluded) {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, inputFile{
			name: filepath.ToSlash(relative),
			size: uint64(info.Size()),
			open: func() (io.ReadCloser, error) {
				file, err := os.Open(path)
				if err != nil {
					return nil, err
				}
				current, err := file.Stat()
				if err != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || current.Size() != info.Size() {
					file.Close()
					if err != nil {
						return nil, err
					}
					return nil, fmt.Errorf("file changed during scan: %s", relative)
				}
				return file, nil
			},
		})
		return nil
	})
	if err != nil {
		return nil, nil, 0, err
	}
	return scanFiles(files, rules)
}
