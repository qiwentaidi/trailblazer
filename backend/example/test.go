package main

import "regexp"

var Email = regexp.MustCompile(`\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*`)

func main() {
	content := `
	...,{staticClass:"iconfont icon-icon-email"}),n("div",{staticClass:"info"},[n("span",[t._v("邮箱 丨 635926424@qq.com")]),n("img",{staticClass:"jiantou",attrs:{src:i("cbef")}})])])},function(){var t=this,e=t.$createEl...
	`
	emails := Email.FindAllString(content, -1)
	for _, email := range emails {
		println(email)
	}
}
