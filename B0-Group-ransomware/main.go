package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"

	"github.com/speps/go-hashids/v2"
	"golang.org/x/crypto/pbkdf2"
)

var BLOCKSIZE int = 0x400000 + 0x10
var r = regexp.MustCompile(`\.id-[a-zA-Z0-9]{9}\.B0-[a-f0-9]+`)

func sha1Hash(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return hex.EncodeToString(bs)
}
func md5Hash(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return hex.EncodeToString(bs)
}
func sha512Hash(s string) string {
	h := sha512.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return hex.EncodeToString(bs)
}

func decryptFile(filename string, outFilename string, key []byte) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("decryptFile : error opening %s : %s", filename, err)
	}
	defer file.Close()
	outFile, err := os.Create(outFilename)
	if err != nil {
		return fmt.Errorf("decryptFile : error creating %s : %s", outFilename, err)
	}
	defer outFile.Close()

	// read the IV from the file
	var iv [12]byte
	file.Seek(0x10, 0)
	_, err = file.Read(iv[:])
	if err != nil {
		return fmt.Errorf("decryptFile : error reading IV from : %s", err)
	}
	ciphertext := make([]byte, BLOCKSIZE)
	plaintext := make([]byte, BLOCKSIZE)
	aesCipher, _ := aes.NewCipher(key)
	aesGcm, _ := cipher.NewGCMWithNonceSize(aesCipher, 12)
	for {
		// read the rest of the file in blocks of BLOCKSIZE
		n, err := file.Read(ciphertext)
		if err != nil {
			if err == io.EOF {
				break // end of file
			}
			return fmt.Errorf("decryptFile : error reading block : %s", err)
		}
		_, err = aesGcm.Open(plaintext[:0], iv[:], ciphertext[:n], nil)
		if err != nil {
			return fmt.Errorf("decryptFile : error decrypting block : %s", err)
		}
		// write the plaintext to the output file
		_, err = outFile.Write(plaintext[:n-0x10])
		if err != nil {
			return fmt.Errorf("decryptFile : error writing block to %s : %s", outFilename, err)
		}
		if n < BLOCKSIZE {
			break // end of file
		}
	}
	return nil
}
func checkIfEncrypted(filepath string) (bool, error) {

	//check if file is encrypted
	matches := r.FindAllString(filepath, 1)
	if len(matches) == 0 {
		return false, nil
	}
	//check if file size is sane
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return false, fmt.Errorf("checkIfEncrypted : error getting file size: %s", err)
	}
	if fileInfo.Size() <= 28 {
		return false, fmt.Errorf("checkIfEncrypted : file size is too small to be encrypted")
	}

	//check if file has the 0x10 NULL byte marker
	file, err := os.Open(filepath)
	if err != nil {

		return false, fmt.Errorf("checkIfEncrypted : error opening file : %s", err)
	}
	defer file.Close()
	buf := make([]byte, 0x10)
	_, err = file.Read(buf)
	if err != nil {
		return false, fmt.Errorf("checkIfEncrypted : error reading marker: %s", err)
	}

	//check if the marker is completely null
	for _, b := range buf {
		if b != 0x00 {
			return false, fmt.Errorf("checkIfEncrypted : marker is missing")
		}
	}

	//check if original file already exists
	_, err = os.Stat(r.ReplaceAllString(filepath, ""))
	if err == nil {
		return false, fmt.Errorf("checkIfEncrypted : original file already exists")
	}
	return true, nil
}
func initLogger() (*log.Logger, error) {
	file, err := os.OpenFile("log.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("initlogger : failed to open log file: %v", err)
	}
	errorLog := log.New(file, "ERROR: ", log.LstdFlags|log.Lshortfile)
	return errorLog, nil
}

func main() {

	errorLog, err := initLogger()
	if err != nil {
		fmt.Printf("%v \n", err)
		return
	}

	encryptedFilePath := flag.String("path", "", "Path to the encrypted file")
	dirPath := flag.String("dirpath", "", "Path to the directory for recursively decrypting files.")
	key := flag.String("key", "", "Key to use for decryption, in the following filename test.pdf.id-QVKGBICKS.B0-3e72d, QVKGBICKS is the key.")
	flag.Parse()
	fmt.Println(*encryptedFilePath)
	if *encryptedFilePath == "" && *dirPath == "" {
		flag.Usage()
		fmt.Println("please provide either a file path or a directory to decrypt")
		return
	}
	if *encryptedFilePath != "" && *dirPath != "" {
		fmt.Println("please provide a file path or a directory to decrypt")
		flag.Usage()
		return
	}
	if *key == "" {
		fmt.Println("please provide a key")
		flag.Usage()
		return
	}
	hd := hashids.NewData()
	hd.Salt = *key
	hd.Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	h, _ := hashids.NewWithData(hd)
	e, _ := h.Encode([]int{0x3B9ACA00})
	password := sha1Hash(md5Hash(md5Hash(sha1Hash(sha512Hash(md5Hash(sha1Hash(e)))))))
	aesKey := pbkdf2.Key([]byte(password), []byte(password), 100000, 32, sha512.New)
	fmt.Printf("AES-GCM key: %x\n", aesKey)
	if *encryptedFilePath != "" {
		// decrypt a single file
		encrypted, err := checkIfEncrypted(*encryptedFilePath)
		if err != nil {
			errorLog.Printf("FILE : %s | ERR : %s\n", *encryptedFilePath, err)
			return
		}
		if !encrypted {
			return
		}
		if r.ReplaceAllString(*encryptedFilePath, "") == *encryptedFilePath || r.ReplaceAllString(*encryptedFilePath, "") == "" {
			errorLog.Printf("FILE : %s | ERR : failed to remove extension.\n", *encryptedFilePath)
			return
		}
		err = decryptFile(*encryptedFilePath, r.ReplaceAllString(*encryptedFilePath, ""), aesKey)
		if err != nil {
			//delete the file if it wasn't decrypted successfully
			_, err := os.Stat(r.ReplaceAllString(*encryptedFilePath, ""))
			if err == nil {
				os.Remove(r.ReplaceAllString(*encryptedFilePath, ""))
			}
			errorLog.Printf("FILE : %s | ERR : %s\n", *encryptedFilePath, err)
			return
		}
	} else if *dirPath != "" {
		// decrypt all files in a directory
		maxWorkers := runtime.GOMAXPROCS(0) * 2
		semaphore := make(chan struct{}, maxWorkers)
		var wg sync.WaitGroup
		e := filepath.Walk(*dirPath, func(path string, f os.FileInfo, err error) error {
			if f.IsDir() {
				return nil
			}
			encrypted, err := checkIfEncrypted(path)
			if err != nil {
				errorLog.Printf("FILE : %s | ERR : %s\n", path, err)
				return nil
			}
			if encrypted {
				wg.Add(1)
				go func(filePath string) {
					semaphore <- struct{}{}

					// release semaphore and mark as done when goroutine completes
					defer func() {
						<-semaphore
						wg.Done()
					}()
					outputPath := r.ReplaceAllString(filePath, "")
					if outputPath == filePath || outputPath == "" {
						errorLog.Printf("FILE : %s | ERR : failed to remove extension.\n", filePath)
						return
					}
					err := decryptFile(filePath, outputPath, aesKey)
					if err != nil {
						errorLog.Printf("FILE : %s | ERR : %s\n", filePath, err)
						// check if the decrypted file exists
						_, err := os.Stat(outputPath)
						if err == nil {
							// delete the decrypted file
							os.Remove(outputPath)
						}
					}
				}(path)
			}
			return nil
		})
		wg.Wait()
		if e != nil {
			fmt.Println("filepath walk err : ", e)
			return
		}
		return
	}
}
