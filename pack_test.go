package tarutil

import (
	"context"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	_ "crypto/sha256"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

func generateWord(length int) string {
	a := int('a')
	z := int('z')
	str := ""

	for l := 0; l < length; l++ {
		pos := rand.Intn(z - a)
		str += string(rune(a + pos))
	}

	return str
}

func generateFiles(num, filelen int) (string, []string, error) {
	basePath, err := ioutil.TempDir("", "")
	if err != nil {
		return "", nil, err
	}

	random, err := os.Open("/dev/urandom")
	if err != nil {
		return "", nil, err
	}

	if err := os.MkdirAll(basePath, 0700); err != nil {
		return "", nil, err
	}

	ret := []string{}

	for i := 0; i < num; i++ {
		fn := generateWord(filelen)
		fullPath := filepath.Join(basePath, fn)
		f, err := os.Create(fullPath)
		if err != nil {
			return "", nil, err
		}

		if _, err := io.Copy(f, io.LimitReader(random, rand.Int63n(1000000))); err != nil {
			return "", nil, err
		}

		f.Close()

		if err := os.Symlink(fullPath, fullPath+".symlink"); err != nil {
			return "", nil, err
		}

		if err := os.Link(fullPath, fullPath+".lnk"); err != nil {
			return "", nil, err
		}

		ret = append(ret, f.Name())
		ret = append(ret, f.Name()+".symlink")
		ret = append(ret, f.Name()+".lnk")
	}

	return basePath, ret, nil
}

func TestPackUnpack(t *testing.T) {
	packDir, files, err := generateFiles(10, 15)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(packDir)

	r, err := Pack(context.Background(), packDir)
	if err != nil {
		t.Fatal(err)
	}

	unpackDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(unpackDir)

	dg := digest.SHA256.Digester()
	dg2 := digest.SHA256.Digester()

	pipeR, pipeW := io.Pipe()
	go func() {
		_, err := io.Copy(pipeW, io.TeeReader(r, dg.Hash()))
		pipeW.CloseWithError(err)
	}()

	if err := Unpack(context.Background(), io.TeeReader(pipeR, dg2.Hash()), unpackDir, nil); err != nil {
		t.Fatal(err)
	}

	if dg.Digest() != dg2.Digest() {
		t.Logf("pack: %v", dg.Digest())
		t.Logf("unpack: %v", dg2.Digest())
		t.Fatal("Digest from Pack did not match digest from Unpack")
	}

	var count int

	if err := filepath.Walk(unpackDir, walkUnpack(unpackDir, files, &count)); err != nil {
		t.Fatalf("Aborted due to missing file: error: %v", err)
	}

	if len(files) != count {
		t.Fatalf("Only walked %d/%d files for some reason...", count, len(files))
	}
}

func TestPackUnpackWithFilter(t *testing.T) {
	packDir, files, err := generateFiles(10, 15)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(packDir)

	r, err := Pack(context.Background(), packDir)
	if err != nil {
		t.Fatal(err)
	}

	unpackDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(unpackDir)

	r, err = FilterTarUsingFilter(r, NewOverlayWhiteouts())
	if err != nil {
		t.Fatal(err)
	}

	dg := digest.SHA256.Digester()
	dg2 := digest.SHA256.Digester()

	pipeR, pipeW := io.Pipe()
	go func() {
		_, err := io.Copy(pipeW, io.TeeReader(r, dg.Hash()))
		pipeW.CloseWithError(err)
	}()

	if err := Unpack(context.Background(), io.TeeReader(pipeR, dg2.Hash()), unpackDir, nil); err != nil {
		t.Fatal(err)
	}

	if dg.Digest() != dg2.Digest() {
		t.Logf("pack: %v", dg.Digest())
		t.Logf("unpack: %v", dg2.Digest())
		t.Fatal("Digest from Pack did not match digest from Unpack")
	}

	var count int

	if err := filepath.Walk(unpackDir, walkUnpack(unpackDir, files, &count)); err != nil {
		t.Fatalf("Aborted due to missing file: error: %v", err)
	}

	if len(files) != count {
		t.Fatalf("Only walked %d/%d files for some reason...", count, len(files))
	}
}

func walkUnpack(unpackDir string, files []string, count *int) func(string, os.FileInfo, error) error {
	return func(p string, fi os.FileInfo, err error) error {
		if p == unpackDir {
			return nil
		}

		*count++
		abort := p

		for _, file := range files {
			if path.Base(file) == path.Base(p) {
				switch path.Ext(p) {
				case ".symlink":
					fi, err := os.Lstat(p)
					if err != nil {
						return err
					}

					if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
						return errors.Errorf("symlink %q was not a symlink", p)
					}

					pristine, err := filepath.EvalSymlinks(p)
					if err != nil {
						return err
					}

					if pristine != strings.TrimSuffix(p, ".symlink") {
						return errors.Errorf("symlink %q did not link to regular file", p)
					}
				case ".lnk":
					fi, err := os.Lstat(p)
					if err != nil {
						return err
					}

					pristine, err := os.Lstat(strings.TrimSuffix(p, ".lnk"))
					if err != nil {
						return err
					}

					if pristine.Sys().(*syscall.Stat_t).Ino != fi.Sys().(*syscall.Stat_t).Ino {
						return errors.Errorf("%q is not a hard link to %q", p, pristine.Name())
					}
				}

				abort = ""
			}
		}

		if len(abort) != 0 {
			return errors.Errorf("missed file %q", abort)
		}

		return nil
	}
}
