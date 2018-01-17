// Add a remote TLS certificate to a local Java keystore
// Requires a Java environment
// Return codes:
//      1: wrong usage (commandline arguments)

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

const (
	maxBackup = 1000
)

var (
	maxBackupLimitReached = fmt.Errorf("maximum number of %d backups "+
		"reached\n", maxBackup)
)

func main() {
	chain := flag.Bool("chain", true, "Import complete CA chain")
	insecure := flag.Bool("insecure", true, "Allow custom cert path")
	keep := flag.Bool("keep", false,
		"Keep interim certificates in temporary directory")
	passwd := flag.String("keystorepasswd", "changeit",
		"keystore password")
	flag.Parse()
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [host:port]...\n",
			os.Args[0])
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	keystore := locate()
	err := numberedBackup(keystore, maxBackup)
	die(err)

	// Fetch remote cert
	for _, addr := range flag.Args() {
		var cfg tls.Config
		if *insecure {
			cfg.InsecureSkipVerify = true
		}
		conn, err := tls.Dial("tcp", addr, &cfg)
		die(err)
		conn.Handshake()
		certs := conn.ConnectionState().PeerCertificates
		log.Printf("%s: %d certs (%T)\n", addr, len(certs), certs)
		for i, c := range certs {
			log.Printf("--------------------------------------\n")
			// log.Printf("cert: %+v\n", c)
			log.Printf("Issuer: %+v\n", c.Issuer)
			log.Printf("IssuingCertificateURL: %+v\n",
				c.IssuingCertificateURL)

			f, err := persist(c)
			die(err)

			alias := fmt.Sprintf("%s_%d", addr, i)
			addCert(keystore, *passwd, f, alias)

			// defer()ing can result in resource saturation such as
			// maximum number of open files e.a., but a common cert
			// chain usually consists of < 10 certs.
			if *keep {
				log.Printf("keeping interim file %s\n", f)
			} else {
				defer os.Remove(f)
			}

			if *chain {
				caf, err := fetchIssuer(*c)
				die(err)
				addCert(keystore, *passwd, caf,
					filepath.Base(caf))
				if *keep {
					log.Printf("keeping interim file %s\n",
						caf)
				} else {
					defer os.Remove(caf)
				}
			}
		}
	}
}

func addCert(keystore, password, certfilename, alias string) {
	safePart := []string{
		filepath.Join(javaHome(), "jre/bin/keytool"),
		"-import",
		"-noprompt",
		"-trustcacerts",
		"-alias", alias,
		"-keystore", keystore,
		"-file", certfilename,
	}
	log.Printf("executing %+v\n", safePart)
	sensitivePart := []string{"--storepass", password}
	both := append(safePart, sensitivePart...)
	cmd := exec.Command(both[0], both[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	die(err)
}

func die(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func fetchIssuer(c x509.Certificate) (string, error) {
	// Should we support multiple URLs?
	url := c.IssuingCertificateURL[0]
	log.Printf("fetching referenced CA %s\n", url)
	res, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	filename := filepath.Join(os.TempDir(), path.Base(url))
	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(filename, buf, 0600); err != nil {
		return "", err
	}
	log.Printf("wrote %s\n", filename)

	return filename, nil
}

func javaHome() string {
	return os.Getenv("JAVA_HOME")
}

// Create a numbered backup à la cp --numbered-backup
func nextBackup(filename string, maxBackup int) (string, error) {
	for i := 0; i < maxBackup; i++ {
		s := fmt.Sprintf("%s.%d", filename, i)
		_, err := os.Stat(s)
		if os.IsNotExist(err) {
			return s, nil
		} else {
			die(err)
		}

	}
	return "", maxBackupLimitReached
}

func numberedBackup(filename string, maxBackup int) error {
	dest, err := nextBackup(filename, maxBackup)
	log.Printf("creating backup %s\n", dest)
	if err != nil {
		return err
	}
	// Certs are small, so we can use in-memory approach
	buf, err := ioutil.ReadFile(filename)
	die(err)

	// Create new file with same perms
	fi, err := os.Stat(filename)
	die(err)

	if err := ioutil.WriteFile(dest, buf, fi.Mode()); err != nil {
		log.Fatal(err)
	}
	log.Printf("created backup %s\n", dest)
	return nil
}

func locate() string {
	val := javaHome()
	if len(val) == 0 {
		// TODO determine via 'which java' and following links
		log.Fatalf("missing JAVA_HOME")
	}
	p := filepath.Join(val, "jre/lib/security/cacerts")
	resolved, err := filepath.EvalSymlinks(p)
	die(err)
	return resolved
}

func persist(cert *x509.Certificate) (string, error) {
	// Write to tmp directory
	tmpfile, err := ioutil.TempFile("", "cert-")
	if err != nil {
		return "", err
	}
	pem.Encode(tmpfile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	tmpfile.Close()
	return tmpfile.Name(), nil
}
