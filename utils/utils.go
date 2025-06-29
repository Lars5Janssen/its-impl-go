package utils

import "log"

var l *log.Logger

type InitData struct {
	Logger *log.Logger
}

func Init(d InitData) {
	l = d.Logger
}

func CheckFatal(msg string, e error) {
	if e != nil {
		l.Fatalln(msg, e.Error())
	}
}

func Check(msg string, e error) {
	if e != nil {
		l.Println(msg, e.Error())
	}
}
