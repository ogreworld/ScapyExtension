#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# http://tools.ietf.org/html/rfc2616
# Author : Steeve Barbeau
# Twitter : @steevebarbeau
# Blog : steeve-barbeau.blogspot.com

import re

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP


class HTTPRequest(Packet):
	name = "HTTPRequest"
	http_methods = "^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)"
	fields_desc=[StrField("method", None, fmt="H"),
				StrField("host", None, fmt="H"),
				StrField("user_agent", None, fmt="H"),
				StrField("accept", None, fmt="H"),
				StrField("accept_language", None, fmt="H"),
				StrField("accept_encoding", None, fmt="H"),
				StrField("accept_charset", None, fmt="H"),
				StrField("referer", None, fmt="H"),
				StrField("authorization", None, fmt="H"),
				StrField("expect", None, fmt="H"),
				StrField("from", None, fmt="H"),
				StrField("if_Match", None, fmt="H"),
				StrField("if_modified_since", None, fmt="H"),
				StrField("if_none_match", None, fmt="H"),
				StrField("if_range", None, fmt="H"),
				StrField("if_unmodified_since", None, fmt="H"),
				StrField("max_forwards", None, fmt="H"),
				StrField("proxy_authorization", None, fmt="H"),
				StrField("range", None, fmt="H"),
				StrField("TE", None, fmt="H")]


	def do_dissect(self, s):
		fields_rfc = ["method", "host", "user_agent", "accept", "accept_language", "accept_encoding", "accept_charset", "referer", "authorization", "expect", "from", "if_match", "if_modified_since", "if_none_match", "if_range", "if_unmodified_since", "max_forwards", "proxy_authorization", "range", "TE"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				if(g=="method"):
					prog=re.compile(self.http_methods)
				else:
					prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return '\r\n'+"".join(a)


class HTTPResponse(Packet):
	name = "HTTPResponse"
	fields_desc=[StrField("status_line", None, fmt="H"),
				StrField("accept_ranges", None, fmt="H"),
				StrField("age", None, fmt="H"),
				StrField("etag", None, fmt="H"),
				StrField("location", None, fmt="H"),
				StrField("proxy_authenticate", None, fmt="H"),
				StrField("retry_after", None, fmt="H"),
				StrField("server", None, fmt="H"),
				StrField("vary", None, fmt="H"),
				StrField("www_authenticate", None, fmt="H")]

	def do_dissect(self, s):
		fields_rfc = ["status_line","accept_ranges","age","etag","location","proxy_authenticate", "retry_after", "server", "vary", "www_authenticate"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				if(g=="status_line"):
					prog=re.compile("^HTTP/((0\.9)|(1\.0)|(1\.1))\ [0-9]{3}.*")
				else:
					prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return '\r\n'+"".join(a)


class HTTP(Packet):
	name="HTTP"
	fields_desc = [StrField("cache_control", None, fmt="H"),
					StrField("connection", None, fmt="H"),
					StrField("date", None, fmt="H"),
					StrField("pragma", None, fmt="H"),
					StrField("trailer", None, fmt="H"),
					StrField("transfer_encoding", None, fmt="H"),
					StrField("upgrade", None, fmt="H"),
					StrField("via", None, fmt="H"),
					StrField("warning", None, fmt="H"),
					StrField("keep_alive", None, fmt="H"),
					StrField("allow", None, fmt="H"),
					StrField("content_encoding", None, fmt="H"),
					StrField("content_language", None, fmt="H"),
					StrField("content_length", None, fmt="H"),
					StrField("content_location", None, fmt="H"),
					StrField("content_MD5", None, fmt="H"),
					StrField("content_range", None, fmt="H"),
					StrField("content_type", None, fmt="H"),
					StrField("expires", None, fmt="H"),
					StrField("last_modified", None, fmt="H")]

	def do_dissect(self, s):
		fields_rfc = ["cache_control", "connection", "date", "pragma", "trailer", "transfer_encoding", "upgrade", "via", "warning", "keep_alive", "allow", "content_encoding", "content_language", "content_length", "content_location", "content_MD5", "content_range", "content_type", "expires", "last_modified"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return "\r\n".join(a)
	
	def guess_payload_class(self, payload):
		prog=re.compile("^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)")
		result=prog.search(payload)
		if result:
			return HTTPRequest
		else:
			prog=re.compile("^HTTP/((0\.9)|(1\.0)|(1\.1))\ [0-9]{3}.*")
			result=prog.search(payload)
			if result:
				return HTTPResponse
		return Packet.guess_payload_class(self, payload)


bind_layers(TCP, HTTP, dport=80)


if __name__ == "__main__":
	interact(mydict=globals(), mybanner="HTTP Scapy extension")
	
	