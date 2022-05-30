package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
)

const BUFFER = 1e6

var wg sync.WaitGroup

type Block struct {
	Index int
	Body  []byte
	Hash  []byte
}

type Options struct {
	All   bool
	New   bool
	Clear bool
	Quiet bool
}

type Required struct {
	Source string
}

type Routine struct {
	ID   int
	Name string
	End  chan bool
}

type FileCutter struct {
	Routine
}

type BlockHasher struct {
	Routine
}

func check(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (rt *Routine) fileCutter(name string, cmp chan bool, cs chan Block, b chan Block) string {
	var parts int
	var sum []byte

	file, err := os.OpenFile(name, os.O_RDONLY, os.ModePerm)
	checkFatal(err)
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
		}
	}(file)

	for {
		var block Block
		block.Body = make([]byte, BUFFER)
		n, err := file.Read(block.Body)
		if n == 0 || err == io.EOF {
			break
		}
		if n < len(block.Body) {
			block.Body = block.Body[:n]
		}
		block.Index = parts
		b <- block
		parts++
		block = Block{}
	}
	for i := 0; i < parts; i++ {
		<-cmp
	}
	hasher := sha1.New()
	blocks := make(map[int][]byte)
	for i := 0; i < parts; i++ {
		temp := <-cs
		blocks[temp.Index] = temp.Hash
	}
	for i := 0; i < parts; i++ {
		hasher.Write(blocks[i])
	}
	sum = hasher.Sum(nil)
	return fmt.Sprintf("%x", sum)
}

func (rt *Routine) blockHasher(cmp chan bool, cs chan Block, b chan Block) {
	for {
		select {
		case <-rt.End:
			wg.Done()
			return
		case block := <-b:
			hasher := sha1.New()
			_, _ = hasher.Write(block.Body)
			block.Hash = hasher.Sum(nil)
			block.Body = nil
			cs <- block
			cmp <- true
			block = Block{}
		}
	}
}

func (rt *Routine) stop() {
	log.Printf("Routine [%s] is stopping", rt.Name)
	rt.End <- true
}

func showHelp() {
	fmt.Println(`Usage:
hashgen [-a] [-c] [-q] [-h] source

required args:
source

optional args:
a       Regenerate all hashes
c       Clear hash orphans
q       Quiet mode, no output`)
}

func Checkout(args []string) (opt Options, req Required, err error) {
	var tail []string
	if len(args) == 0 {
		showHelp()
		os.Exit(0)
	}
	for _, v := range args {
		switch v[0] {
		case '-':
			switch v[1] {
			case 'h':
				showHelp()
				os.Exit(0)
			case 'a':
				opt.All = true
			case 'c':
				opt.Clear = true
			case 'q':
				opt.Quiet = true
			default:
				showHelp()
				os.Exit(0)
			}
		default:
			tail = append(tail, v)
		}
	}
	if !opt.All {
		opt.New = true
	}
	if len(tail) != 1 {
		showHelp()
		os.Exit(0)
	} else {
		req.Source = strings.TrimRight(tail[0], "/\\")
		if _, err = os.ReadDir(req.Source); err != nil {
			return Options{}, Required{}, err
		}
	}
	return
}

func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

func ClearOrphans(orphans []string, shaMap map[string]string) {
	for _, v := range orphans {
		delete(shaMap, v)
	}
}

func RewriteShaFile(shaFile *os.File, shaMap map[string]string) {
	var shaNames []string
	err := shaFile.Truncate(0)
	check(err)
	_, err = shaFile.Seek(0, 0)
	check(err)
	for k := range shaMap {
		shaNames = append(shaNames, k)
	}
	sort.Strings(shaNames)
	for _, v := range shaNames {
		str := fmt.Sprintf("%s   %s\r\n", shaMap[v], v)
		_, err = shaFile.WriteString(str)
	}
}

type Print struct {
	Str   string
	Type  int
	Quiet bool
}

func logPrint(p chan Print) {
	types := []string{"Removing orphans", "Generating hash for:"}
	line := 5 // out of array
	for {
		msg := <-p
		if line == msg.Type {
			if !msg.Quiet {
				fmt.Println(types[msg.Type], msg.Str)
			}
		} else {
			line = msg.Type
			if !msg.Quiet {
				fmt.Println("")
				fmt.Println(types[msg.Type], msg.Str)
			}
		}
	}
}

func main() {

	completed := make(chan bool, 1e6)
	checksums := make(chan Block, 1e6)
	blocks := make(chan Block, 32)
	prints := make(chan Print, 1)

	// разбор параметров
	opt, req, err := Checkout(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	Q := opt.Quiet

	// чтение директории
	dirEntry, err := os.ReadDir(req.Source)
	if err != nil {
		log.Fatal(err)
	}
	var files []string
	for _, entry := range dirEntry {
		files = append(files, entry.Name())
	}

	// чтение файла .sha1
	var rd *bufio.Reader
	var shaFile *os.File
	path := fmt.Sprintf(req.Source + string(os.PathSeparator) + ".sha1")
	shaFile, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE, os.ModePerm)
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
		}
	}(shaFile)

	// разбор файла .sha1
	// shaMap - словарь [name]: [checksum]
	shaMap := make(map[string]string)
	rd = bufio.NewReader(shaFile)
	for {
		line, err := rd.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatal("something wrong with .sha1")
			}
		}
		hash := strings.Split(line, "   ")
		shaMap[hash[1]] = hash[0]
	}

	// удаляем из списка files файл .sha1
	for k, v := range files {
		if v == ".sha1" {
			files = append(files[:k], files[k+1:]...)
			break
		}
	}

	// вычисляем файлы которых нет в .sha1
	var news, orphans []string
	for _, v := range files {
		_, ok := shaMap[v]
		if !ok {
			news = append(news, v)
		}
	}

	// вычисляем записи в sha1 без файлов
	for k := range shaMap {
		_, found := Find(files, k)
		if !found {
			orphans = append(orphans, k)
		}
	}

	// если флаг -c - чистим .sha1
	// и заполняем актуальными суммами
	if opt.Clear {
		prints <- Print{Str: " ", Type: 0, Quiet: Q}
		ClearOrphans(orphans, shaMap)
		RewriteShaFile(shaFile, shaMap)
		if !opt.All && !opt.New {
			os.Exit(0)
		}
	}

	var fc FileCutter
	var pointers []*Routine

	defer wg.Wait()

	go logPrint(prints)
	cpus := runtime.NumCPU() - 2
	if cpus < 1 {
		cpus = 1
	}
	fc = FileCutter{Routine: Routine{Name: "FileCutter", End: make(chan bool, 1)}}
	for i := 0; i < cpus; i++ {
		bh := BlockHasher{Routine: Routine{Name: "BlockHasher", End: make(chan bool, 1)}}
		pointers = append(pointers, &bh.Routine)
		go bh.blockHasher(completed, checksums, blocks)
		wg.Add(1)
	}
	defer func() {
		for _, pts := range pointers {
			pts.End <- true
		}
		wg.Wait()
	}()

	// если все файлы - считаем суммы всех файлов
	if opt.All {
		ClearOrphans(orphans, shaMap)
		for _, v := range files {
			path := fmt.Sprintf(req.Source + string(os.PathSeparator) + v)
			prints <- Print{Str: v, Type: 1, Quiet: Q}
			shaMap[v] = fc.fileCutter(path, completed, checksums, blocks)
		}
		RewriteShaFile(shaFile, shaMap)
	}

	// если только новые файлы - считаем суммы только новых
	if opt.New {
		ClearOrphans(orphans, shaMap)
		for _, v := range news {
			path := fmt.Sprintf(req.Source + string(os.PathSeparator) + v)
			prints <- Print{Str: v, Type: 1, Quiet: Q}
			shaMap[v] = fc.fileCutter(path, completed, checksums, blocks)
		}
		RewriteShaFile(shaFile, shaMap)
	}
}
