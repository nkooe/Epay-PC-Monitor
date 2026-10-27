package main

// 支付宝账单解析。
//
// 实测的页面结构（consumeprod.alipay.com/record/standard.htm，GBK 编码）：
//
//	<tr id="J-item-1" class="J-item">
//	  <td class="time"><p>今天</p><p class="text-muted">18:29</p></td>
//	  <td class="name">
//	    <p class="consume-title"><a href="...?bizType=TRADE&bizInNo=<交易号>&gmtBizCreate=<时间>">收钱码收款</a></p>
//	    <p class="name p-inline ft-gray">*想 |</p>
//	    <a class="J-tradeNo" data-clipboard-text="<交易号>" title="...">...</a>
//	  </td>
//	  <td class="amount"><span class="amount-pay">+ 0.13</span></td>
//	</tr>
//
// 字段来源：
//   交易号 — data-clipboard-text（最可靠），退路是 href 里的 bizInNo
//   时间   — href 里的 gmtBizCreate，格式 20261025182959
//   金额   — td.amount 里的 +0.13 / -5.00（正数是收款）
//   说明   — p.consume-title 的文本
//   对方   — p.ft-gray 的文本

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reItemRow   = regexp.MustCompile(`(?s)<tr[^>]*class="[^"]*J-item[^"]*"[^>]*>(.*?)</tr>`)
	reTradeText = regexp.MustCompile(`data-clipboard-text="([0-9]{16,32})"`)
	reBizInNo   = regexp.MustCompile(`bizInNo=([0-9]{16,32})`)
	reGmtCreate = regexp.MustCompile(`gmtBizCreate=(\d{14})`)
	reAmountPay = regexp.MustCompile(`class="[^"]*amount-pay[^"]*"[^>]*>\s*([+\-]?)\s*([0-9,]+\.[0-9]{2})`)
	reAmountTd  = regexp.MustCompile(`(?s)<td[^>]*class="[^"]*amount[^"]*"[^>]*>(.*?)</td>`)
	reTitleTxt  = regexp.MustCompile(`(?s)<p[^>]*class="[^"]*consume-title[^"]*"[^>]*>(.*?)</p>`)
	reGrayTxt   = regexp.MustCompile(`(?s)<p[^>]*class="[^"]*ft-gray[^"]*"[^>]*>(.*?)</p>`)
	reAnyTag    = regexp.MustCompile(`(?s)<[^>]+>`)
	reSpaces    = regexp.MustCompile(`\s+`)
)

// parseAlipayBillHTML 从账单页 HTML 解析收款记录。
// 只返回正数金额（进账）；支出行会被跳过。
func parseAlipayBillHTML(html string) []AlipayBill {
	if strings.TrimSpace(html) == "" {
		return nil
	}

	rows := reItemRow.FindAllStringSubmatch(html, -1)
	if len(rows) == 0 {
		// 兼容旧结构 / 测试样例
		return parseAlipayBillLegacy(html)
	}

	out := make([]AlipayBill, 0, len(rows))
	seen := map[string]bool{}

	for _, r := range rows {
		seg := r[1]

		trade := ""
		if m := reTradeText.FindStringSubmatch(seg); len(m) > 1 {
			trade = m[1]
		} else if m := reBizInNo.FindStringSubmatch(seg); len(m) > 1 {
			trade = m[1]
		}
		if trade == "" || strings.HasPrefix(trade, "2088") || seen[trade] {
			continue
		}

		sign, amtStr := "", ""
		if m := reAmountPay.FindStringSubmatch(seg); len(m) > 2 {
			sign, amtStr = m[1], m[2]
		} else if m := reAmountTd.FindStringSubmatch(seg); len(m) > 1 {
			inner := stripHTMLTags(m[1])
			if mm := regexp.MustCompile(`([+\-]?)\s*([0-9,]+\.[0-9]{2})`).FindStringSubmatch(inner); len(mm) > 2 {
				sign, amtStr = mm[1], mm[2]
			}
		}
		amtStr = strings.ReplaceAll(amtStr, ",", "")
		if amtStr == "" {
			continue
		}
		amt, err := strconv.ParseFloat(amtStr, 64)
		if err != nil || amt <= 0 {
			continue
		}
		// 带减号的是支出，跳过
		if sign == "-" {
			continue
		}

		tm := ""
		if m := reGmtCreate.FindStringSubmatch(seg); len(m) > 1 {
			tm = formatGmtCreate(m[1])
		}

		// 说明优先取 consume-title 的文本；但转账类的 title 是对方订单号（纯数字），
		// 这种要用下面 ft-gray 里的备注（如 "Kudi-转账"）。
		memo := ""
		if m := reTitleTxt.FindStringSubmatch(seg); len(m) > 1 {
			if v := strings.TrimSpace(stripHTMLTags(m[1])); v != "" && !isAllDigits(v) {
				memo = v
			}
		}
		if memo == "" {
			if m := reGrayTxt.FindStringSubmatch(seg); len(m) > 1 {
				v := strings.TrimSpace(stripHTMLTags(m[1]))
				v = strings.TrimSpace(strings.TrimRight(v, "|"))
				if v != "" {
					memo = v
				}
			}
		}
		if memo == "" {
			memo = "支付宝收款"
		}

		seen[trade] = true
		out = append(out, AlipayBill{
			TradeNo: trade,
			Amount:  amt,
			Time:    tm,
			Memo:    memo,
		})
	}
	return out
}

// formatGmtCreate 把 20261025182959 转成 2026-10-25 18:29:59
func formatGmtCreate(s string) string {
	if len(s) != 14 {
		return ""
	}
	return s[0:4] + "-" + s[4:6] + "-" + s[6:8] + " " + s[8:10] + ":" + s[10:12] + ":" + s[12:14]
}

// isAllDigits 判断是不是纯数字（转账行的 title 是对方订单号）
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func stripHTMLTags(s string) string {
	s = reAnyTag.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "\u00a0", " ")
	s = unescapeUnicode(s)
	return strings.TrimSpace(reSpaces.ReplaceAllString(s, " "))
}

var reUnicodeEsc = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

// unescapeUnicode 还原页面里的 \uXXXX 转义。
// 支付宝的转账备注在 HTML 里是 "\u004b\u0075\u0064\u0069-转账" 这种形式，
// 不还原的话界面上直接显示成 \u004b\u0075\u0064\u0069。
func unescapeUnicode(s string) string {
	if !strings.Contains(s, "\\u") {
		return s
	}
	return reUnicodeEsc.ReplaceAllStringFunc(s, func(m string) string {
		h := m[len(m)-4:]
		var v int
		for _, c := range h {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v += int(c - '0')
			case c >= 'a' && c <= 'f':
				v += int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v += int(c-'A') + 10
			}
		}
		return string(rune(v))
	})
}

// parseAlipayBillLegacy 兼容之前的简单结构（单元测试用）
func parseAlipayBillLegacy(html string) []AlipayBill {
	reTR := regexp.MustCompile(`(?s)<tr[^>]*>(.*?)</tr>`)
	reDiv := regexp.MustCompile(`(?s)<div[^>]*class="[^"]*(?:record|item|bill)[^"]*"[^>]*>(.*?)</div>\s*(?:</div>)?`)
	reNo := regexp.MustCompile(`(?:tradeNo[="'\s:]*)?\b(20[0-9]{14,30})\b`)
	reAmt := []*regexp.Regexp{
		regexp.MustCompile(`[¥￥]\s*([0-9]+\.[0-9]{2})`),
		regexp.MustCompile(`([0-9]+\.[0-9]{2})\s*元`),
		regexp.MustCompile(`(?i)class="?[^"]*amount[^"]*"?[^>]*>\s*[^\d]{0,4}([0-9]+\.[0-9]{2})`),
	}
	reT := regexp.MustCompile(`(20[0-9]{2}[-/][0-9]{2}[-/][0-9]{2}\s+[0-9]{2}:[0-9]{2}(?::[0-9]{2})?)`)
	reMemo := []*regexp.Regexp{
		regexp.MustCompile(`(?i)class="?[^"]*memo[^"]*"?[^>]*>\s*([^<]{1,40})`),
		regexp.MustCompile(`([\p{Han}A-Za-z0-9_\-]{1,16}-转账)`),
		regexp.MustCompile(`收钱码收款`),
	}

	var rows []string
	if m := reTR.FindAllStringSubmatch(html, -1); len(m) >= 1 {
		for _, x := range m {
			rows = append(rows, x[1])
		}
	} else if m := reDiv.FindAllStringSubmatch(html, -1); len(m) >= 1 {
		for _, x := range m {
			rows = append(rows, x[1])
		}
	} else {
		rows = []string{html}
	}

	out := make([]AlipayBill, 0, len(rows))
	seen := map[string]bool{}
	for _, seg := range rows {
		no := ""
		for _, m := range reNo.FindAllStringSubmatch(seg, -1) {
			if len(m) > 1 && !strings.HasPrefix(m[1], "2088") {
				no = m[1]
				break
			}
		}
		if no == "" || seen[no] {
			continue
		}
		amtStr := ""
		for _, re := range reAmt {
			if m := re.FindStringSubmatch(seg); len(m) > 1 {
				amtStr = m[1]
				break
			}
		}
		if amtStr == "" {
			continue
		}
		amt, err := strconv.ParseFloat(amtStr, 64)
		if err != nil || amt <= 0 {
			continue
		}
		tm := ""
		if m := reT.FindStringSubmatch(seg); len(m) > 1 {
			tm = strings.ReplaceAll(m[1], "/", "-")
			if i := strings.Index(tm, " "); i > 0 && strings.Count(tm[i+1:], ":") == 1 {
				tm += ":00"
			}
		}
		memo := "支付宝收款"
		for _, re := range reMemo {
			if m := re.FindStringSubmatch(seg); len(m) > 1 {
				if v := strings.TrimSpace(m[1]); v != "" {
					memo = v
					break
				}
			} else if len(m) == 1 && m[0] != "" {
				memo = m[0]
				break
			}
		}
		seen[no] = true
		out = append(out, AlipayBill{TradeNo: no, Amount: amt, Time: tm, Memo: memo})
	}
	return out
}
