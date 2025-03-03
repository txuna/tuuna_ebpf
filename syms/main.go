package main

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

type Ksym struct {
	Addr    string
	SymName string
	ModName string
}

type Handler struct {
	Ksyms []*Ksym
}

func (h *Handler) Find(addr string) {
	addrNum, err := strconv.ParseUint(addr, 16, 64)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for _, sym := range slices.Backward(h.Ksyms) {
		n, err := strconv.ParseUint(sym.Addr, 16, 64)
		if err != nil {
			fmt.Println("Error: ", err)
			return
		}
		if addrNum >= n {
			fmt.Printf("find: %s -> [%s]-[%s]-[%s]\n", addr, sym.Addr, sym.SymName, sym.ModName)
			break
		}

		continue
	}
}

func main() {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	h := &Handler{
		Ksyms: make([]*Ksym, 0),
	}

	modName := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 공백(Space) 기준으로 Split
		parts := strings.Fields(line)

		// 최소한 "주소, 타입, 심볼 이름"이 존재해야 함
		if len(parts) < 3 {
			continue
		}

		switch parts[1] {
		case "b", "B", "d", "D", "r", "R":
			continue
		}

		if len(parts) == 4 {
			modName = parts[3]
			continue
		}

		h.Ksyms = append(h.Ksyms, &Ksym{
			Addr:    parts[0],
			SymName: parts[2],
			ModName: modName,
		})
	}

	h.Find("ffff8000813b9cc8")
}

// ffff8000813b9cc8
