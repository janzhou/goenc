/*
*   Author: Jian Zhou
*   Email:  zhoujian@tiaozhanshu.com
*   Home:   http://janzhou.org/
*/

package main

import (
    "os"
    "io"
    "fmt"
    "flag"
    "crypto/aes"
    "crypto/rand"
	"encoding/binary"
	"bytes"
    "errors"
    "unsafe"
    "hash"
    "crypto/sha512"
    "crypto/hmac"
)

//indicate the file format
var version int32 = int32(0)

func usage(){
    fmt.Fprintf(os.Stderr, "Version: 0.1\n")
    fmt.Fprintf(os.Stderr, "Author: Jian Zhou\n")
    fmt.Fprintf(os.Stderr, "Email: zhoujian@tiaozhanshu.com\n")
    fmt.Fprintf(os.Stderr, "Usage:\n")
    fmt.Fprintf(os.Stderr, "    goenc -i inputfile -o outputfile -k keyfile\n")
    fmt.Fprintf(os.Stderr, "    goenc -i inputfile -k keyfile --dec=true\n")
    //flag.PrintDefaults()
    os.Exit(0)
}

func getfileinfos(filename string)(buf *bytes.Buffer, filelen int64, err error) {
    buf = new(bytes.Buffer)

    err = binary.Write(buf, binary.LittleEndian, int32(len(filename)))
    if err != nil {
        return buf, filelen, err
    }

    n, err := buf.Write([]byte(filename))
    if err != nil {
        return buf, filelen, err
    }
    if n < len(filename) {
        return buf, filelen, errors.New("buf write filename error")
    }

    info, err := os.Stat(filename)
    filelen = info.Size()
	err = binary.Write(buf, binary.LittleEndian, filelen)
	if err != nil {
        return buf, filelen, err
    }

    return buf, filelen, nil
}

func encodefile(inputfile, outputfile string, passkey []byte){
    in, err := os.Open(inputfile)
	if err != nil {
		fmt.Printf("%s open error\n", inputfile)
		return
	}

    out, err := os.Create(outputfile)
	if err != nil {
		fmt.Printf("%s create error\n", outputfile)
		return
	}

//===============write version number
	err = binary.Write(out, binary.LittleEndian, version)
	if err != nil {
        fmt.Printf("version write error\n")
        return
    }


//===============write encoded random key
	key := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, key)
    if n < 32 || err != nil {
		fmt.Printf("key error\n")
		return
	}
    c, err := aes.NewCipher(passkey[0:32])
    if err != nil {
		fmt.Printf("pass cipher create error\n")
		return
	}
    b := make([]byte, 32)
    c.Encrypt(b[0:16], key[0:16])
    c.Encrypt(b[16:32], key[16:32])
    out.Write(b)
    c, err = aes.NewCipher(key)
    if err != nil {
		fmt.Printf("cipher create error\n", outputfile)
		return
	}

//===============write encoded file infos
    buf, filelen, err := getfileinfos(inputfile)
    if err != nil {
        fmt.Print("getfileinfos error:", err)
        return
    }

	b = make([]byte, c.BlockSize())
	for n, err := buf.Read(b); err == nil && n > 0; n, err = buf.Read(b){
        c.Encrypt(b, b)
        out.Write(b)
    }

//===============write encoded file
	for n, err := in.Read(b); n != 0 && err != io.EOF && filelen > 0; n, err = in.Read(b) {
        c.Encrypt(b, b)
        out.Write(b)
        filelen -= int64(c.BlockSize())
	}

	err =  in.Close()
	err =  out.Close()

    fmt.Print("encrypt finished\n")
}

func decodefile(inputfile string, passkey []byte) {
    in, err := os.Open(inputfile)
	if err != nil {
		fmt.Printf("%s open error\n", inputfile)
		return
	}

//===============read version 0
    var fileversion int32
    err = binary.Read(in, binary.LittleEndian, &fileversion)
	if err != nil {
        fmt.Printf("version read error\n")
        return
    }
    if fileversion != version {
        fmt.Printf("file version error")
        return
    }

//===============read decoded random key
    key := make([]byte, 32)
    n, err := in.Read(key)
    if n < 32 || err != nil {
        fmt.Printf("key error")
        return
    }
    c, err := aes.NewCipher(passkey[0:32])
    if err != nil {
		fmt.Printf("cipher create error\n")
		return
	}
    c.Decrypt(key[0:16], key[0:16])
    c.Decrypt(key[16:32], key[16:32])
    c, err = aes.NewCipher(key)
    if err != nil {
		fmt.Printf("cipher create error\n")
		return
	}

//===============read length of file name
	b := make([]byte, c.BlockSize())
    n, err = in.Read(b)
    if n < c.BlockSize() || err != nil {
        fmt.Printf("read file len error")
        return
    }
    c.Decrypt(b,b)
    buf := new(bytes.Buffer)
    err = binary.Write(buf, binary.LittleEndian, b)
    if err != nil {
        fmt.Print(err)
        return
    }
    var filenamelen int32
    binary.Read(buf, binary.LittleEndian, &filenamelen)

//===============read file name and file length
    var filelen int64
	filename := make([]byte, filenamelen)
    infolen := filenamelen + int32(unsafe.Sizeof(filenamelen)) + int32(unsafe.Sizeof(filelen)) - int32(c.BlockSize())
	if infolen > 0 {
        for n, err = in.Read(b); n > 0 && err != io.EOF; n, err = in.Read(b) {
            c.Decrypt(b, b)
            err = binary.Write(buf, binary.LittleEndian, b)
            if err != nil {
                fmt.Print(err)
                return
            }
            infolen -= int32(c.BlockSize())
            if infolen <= 0 {
                break
            }
	    }
    }
    if infolen > 0 {
        fmt.Print("may be it is not an eccrypted file?\n")
        return
    }
    binary.Read(buf, binary.LittleEndian, &filename)
    binary.Read(buf, binary.LittleEndian, &filelen)

//===============create file with file name
    out, err := os.Create(string(filename))
    if err != nil {
		fmt.Printf("file create error\n")
		return
	}

//===============decrypt file content
    for n, err := in.Read(b); n != 0 && err != io.EOF; n, err = in.Read(b) {
        c.Decrypt(b, b)
        if(filelen > int64(c.BlockSize())){
            filelen -= int64(c.BlockSize())
            out.Write(b)
        }else{
            out.Write(b[0:filelen])
        }
	}

    if filelen > int64(c.BlockSize()) {
        fmt.Print("may be it is not an eccrypted file?\n")
        return
    }

//===============decrypt finished
	err =  in.Close()
	err =  out.Close()

    fmt.Print("decrypt finished\n")
}

func getpasskey(keyfile string)[]byte{
    var password string

    fmt.Print("input password:\n")
    fmt.Print("( the password maybe shown to others, I will fix it in the future )\n")
    n, err := fmt.Scan( &password )
    if err != nil {
        fmt.Print( "get password error\n", err )
        os.Exit(1)
    }

    var h hash.Hash = hmac.New(sha512.New, []byte( password ))

    if len(keyfile) == 0 {
        fmt.Println("Key file is missing.");
        os.Exit(1);
    }

    file, err := os.Open(keyfile)
	if err != nil {
		fmt.Printf("key file open error")
        os.Exit(1);
	}

	b := make([]byte, 1024)
	for n, err = file.Read(b); n != 0 && err != io.EOF; n, err = file.Read(b) {
        h.Write(b[:n])
	}
	err =  file.Close()

    b = h.Sum(nil)
    for i := 0; i < len(b); i++ { //len(b) = 64
        if b[i] >= '0' && b[i] <= '9' {
            b[i] -= '0'
        } else if b[i] >= 'a' && b[i] <= 'f' {
            b[i] -= 'a'
        }
    }
    for i := 0; i < 32; i++ {
        b[i] = b[i] ^ b[i+32]
    }

    return b[0:32]
}

func main() {
    inputfile := flag.String("i", "", "inputfile")
    outputfile := flag.String("o", "", "outputfile")
    keyfile := flag.String("k", "", "keyfile")
    dec := flag.Bool("dec", false, "decrypto")
    v := flag.Bool("v", false, "version")

    flag.Usage = usage
    flag.Parse()

    if *v {
        fmt.Print("Version: 0.1");
        return;
    }

    if inputfile == nil || len(*inputfile) == 0 {
        usage()
        return;
    }

    if *dec {
        decodefile(*inputfile, getpasskey(*keyfile))
    }else {
        if outputfile == nil || len(*outputfile) == 0 {
            usage()
            return;
        }
        encodefile(*inputfile, *outputfile, getpasskey(*keyfile))
    }
}

