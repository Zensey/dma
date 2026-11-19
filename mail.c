/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2008-2014, Simon Schubert <2@0x2c.org>.
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Simon Schubert <2@0x2c.org>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "dma.h"

void
bounce(struct qitem *it, const char *reason)
{
	struct queue bounceq;
	char line[1000];
	size_t pos;
	int error;

	/* Don't bounce bounced mails */
	if (it->sender[0] == 0) {
		syslog(LOG_INFO, "can not bounce a bounce message, discarding");
		delqueue(it);
		exit(EX_SOFTWARE);
	}

	bzero(&bounceq, sizeof(bounceq));
	LIST_INIT(&bounceq.queue);
	bounceq.sender = "";
	if (add_recp(&bounceq, it->sender, EXPAND_WILDCARD) != 0)
		goto fail;

	if (newspoolf(&bounceq) != 0)
		goto fail;

	syslog(LOG_ERR, "delivery failed, bouncing as %s", bounceq.id);
	setlogident("%s", bounceq.id);

	error = fprintf(bounceq.mailf,
		"Received: from MAILER-DAEMON\n"
		"\tid %s\n"
		"\tby %s (%s on %s);\n"
		"\t%s\n"
		"X-Original-To: <%s>\n"
		"From: MAILER-DAEMON <>\n"
		"To: %s\n"
		"Subject: Mail delivery failed\n"
		"Message-Id: <%s@%s>\n"
		"Date: %s\n"
		"\n"
		"This is the %s at %s.\n"
		"\n"
		"There was an error delivering your mail to <%s>.\n"
		"\n"
		"%s\n"
		"\n"
		"%s\n"
		"\n",
		bounceq.id,
		hostname(), VERSION, systemhostname(),
		rfc822date(),
		it->addr,
		it->sender,
		bounceq.id, hostname(),
		rfc822date(),
		VERSION, hostname(),
		it->addr,
		reason,
		config.features & FULLBOUNCE ?
		    "Original message follows." :
		    "Message headers follow.");
	if (error < 0)
		goto fail;

	if (fseek(it->mailf, 0, SEEK_SET) != 0)
		goto fail;
	if (config.features & FULLBOUNCE) {
		while ((pos = fread(line, 1, sizeof(line), it->mailf)) > 0) {
			if (fwrite(line, 1, pos, bounceq.mailf) != pos)
				goto fail;
		}
	} else {
		while (!feof(it->mailf)) {
			if (fgets(line, sizeof(line), it->mailf) == NULL)
				break;
			if (line[0] == '\n')
				break;
			if (fwrite(line, strlen(line), 1, bounceq.mailf) != 1)
				goto fail;
		}
	}

	if (linkspool(&bounceq) != 0)
		goto fail;
	/* bounce is safe */

	delqueue(it);

	run_queue(&bounceq);
	/* NOTREACHED */

fail:
	syslog(LOG_CRIT, "error creating bounce: %m");
	delqueue(it);
	exit(EX_IOERR);
}

struct parse_state {
	char addr[1000];
	int pos;

	enum {
		NONE = 0,
		START,
		MAIN,
		EOL,
		QUIT
	} state;
	int comment;
	int quote;
	int brackets;
	int esc;
};

/*
 * Simplified RFC2822 header/address parsing.
 * We copy escapes and quoted strings directly, since
 * we have to pass them like this to the mail server anyways.
 * XXX local addresses will need treatment
 */
static int
parse_addrs(struct parse_state *ps, char *s, struct queue *queue)
{
	char *addr;

again:
	switch (ps->state) {
	case NONE:
		return (-1);

	case START:
		/* init our data */
		bzero(ps, sizeof(*ps));

		/* skip over header name */
		while (*s != ':')
			s++;
		s++;
		ps->state = MAIN;
		break;

	case MAIN:
		/* all fine */
		break;

	case EOL:
		switch (*s) {
		case ' ':
		case '\t':
			ps->state = MAIN;
			break;

		default:
			ps->state = QUIT;
			if (ps->pos != 0)
				goto newaddr;
			return (0);
		}
		break;

	case QUIT:
		return (0);
	}

	for (; *s != 0; s++) {
		if (ps->esc) {
			ps->esc = 0;

			switch (*s) {
			case '\r':
			case '\n':
				goto err;

			default:
				goto copy;
			}
		}

		if (ps->quote) {
			switch (*s) {
			case '"':
				ps->quote = 0;
				goto copy;

			case '\\':
				ps->esc = 1;
				goto copy;

			case '\r':
			case '\n':
				goto eol;

			default:
				goto copy;
			}
		}

		switch (*s) {
		case '(':
			ps->comment++;
			break;

		case ')':
			if (ps->comment)
				ps->comment--;
			else
				goto err;
			goto skip;

		case '"':
			ps->quote = 1;
			goto copy;

		case '\\':
			ps->esc = 1;
			goto copy;

		case '\r':
		case '\n':
			goto eol;
		}

		if (ps->comment)
			goto skip;

		switch (*s) {
		case ' ':
		case '\t':
			/* ignore whitespace */
			goto skip;

		case '<':
			/* this is the real address now */
			ps->brackets = 1;
			ps->pos = 0;
			goto skip;

		case '>':
			if (!ps->brackets)
				goto err;
			ps->brackets = 0;

			s++;
			goto newaddr;

		case ':':
			/* group - ignore */
			ps->pos = 0;
			goto skip;

		case ',':
		case ';':
			/*
			 * Next address, copy previous one.
			 * However, we might be directly after
			 * a <address>, or have two consecutive
			 * commas.
			 * Skip the comma unless there is
			 * really something to copy.
			 */
			if (ps->pos == 0)
				goto skip;
			s++;
			goto newaddr;

		default:
			goto copy;
		}

copy:
		if (ps->comment)
			goto skip;

		if (ps->pos + 1 == sizeof(ps->addr))
			goto err;
		ps->addr[ps->pos++] = *s;

skip:
		;
	}

eol:
	ps->state = EOL;
	return (0);

err:
	ps->state = QUIT;
	return (-1);

newaddr:
	ps->addr[ps->pos] = 0;
	ps->pos = 0;
	addr = strdup(ps->addr);
	if (addr == NULL)
		errlog(EX_SOFTWARE, NULL);

	if (add_recp(queue, addr, EXPAND_WILDCARD) != 0)
		errlogx(EX_DATAERR, "invalid recipient `%s'", addr);

	goto again;
}

/*
 * Append "@origin" to the address in one comma-separated segment of a
 * From: header if that address has no domain.  Handles "addr",
 * "addr (comment)" and "Display Name <addr>".  Returns the new length of
 * the segment written to out, or 0 if out is too small.
 */
static size_t
qualify_segment(const char *s, size_t n, const char *origin,
    char *out, size_t outsz)
{
	size_t i, a = 0, b = 0, olen = strlen(origin);
	int inq = 0, depth = 0, angle = 0, closed = 0, ins = 0;

	/* Look for <addr> outside quotes and comments. */
	for (i = 0; i < n; i++) {
		if (inq) {
			if (s[i] == '\\' && i + 1 < n)
				i++;
			else if (s[i] == '"')
				inq = 0;
		} else if (depth) {
			if (s[i] == '\\' && i + 1 < n)
				i++;
			else if (s[i] == '(')
				depth++;
			else if (s[i] == ')')
				depth--;
		} else if (s[i] == '"') {
			inq = 1;
		} else if (s[i] == '(') {
			depth = 1;
		} else if (s[i] == '<') {
			angle = 1;
			a = i + 1;
			for (b = a; b < n && s[b] != '>'; b++)
				;
			closed = (b < n);
			break;
		}
	}

	if (angle) {
		if (closed)
			ins = 1;
	} else {
		/* Bare address: first token, not a quoted string. */
		for (i = 0; i < n && (s[i] == ' ' || s[i] == '\t'); i++)
			;
		a = i;
		for (b = a; b < n && s[b] != ' ' && s[b] != '\t' && s[b] != '('; b++)
			;
		if (b > a && s[a] != '"')
			ins = 1;
	}

	/* Nothing to do for empty addresses or those that have a domain. */
	if (ins) {
		if (b == a || memchr(s + a, '@', b - a) != NULL)
			ins = 0;
	}

	if (n + (ins ? olen + 1 : 0) + 1 > outsz)
		return (0);

	if (!ins) {
		memcpy(out, s, n);
		return (n);
	}
	memcpy(out, s, b);
	out[b] = '@';
	memcpy(out + b + 1, origin, olen);
	memcpy(out + b + 1 + olen, s + b, n - b);
	return (n + olen + 1);
}

/*
 * MYORIGIN: complete addresses without a domain in a single-line From:
 * header (e.g. "From: root") with the configured origin domain.  The line
 * (including the trailing newline) is rewritten in place; if the result
 * would not fit, or the header cannot be parsed, it is left unchanged.
 */
static void
qualify_from_header(char *line, size_t size, const char *origin)
{
	char out[1000];
	const char *val = line + 5;	/* after "From:" */
	size_t vlen = strlen(val), o = 0, i, start = 0, w;
	int inq = 0, depth = 0, angle = 0;

	if (vlen > 0 && val[vlen - 1] == '\n')
		vlen--;

	if (o + 5 >= sizeof(out))
		return;
	memcpy(out, "From:", 5);
	o = 5;

	for (i = 0; i <= vlen; i++) {
		if (i < vlen) {
			char c = val[i];
			if (inq) {
				if (c == '\\' && i + 1 < vlen)
					i++;
				else if (c == '"')
					inq = 0;
				continue;
			}
			if (depth) {
				if (c == '\\' && i + 1 < vlen)
					i++;
				else if (c == '(')
					depth++;
				else if (c == ')')
					depth--;
				continue;
			}
			if (c == '"') {
				inq = 1;
				continue;
			}
			if (c == '(') {
				depth = 1;
				continue;
			}
			if (c == '<') {
				angle = 1;
				continue;
			}
			if (c == '>') {
				angle = 0;
				continue;
			}
			if (c != ',' || angle)
				continue;
		}
		/* End of one address segment: val[start..i) */
		w = qualify_segment(val + start, i - start, origin,
		    out + o, sizeof(out) - o - 2);
		if (w == 0 && i > start)
			return;
		o += w;
		if (i < vlen) {
			out[o++] = ',';
			start = i + 1;
		}
	}
	out[o++] = '\n';
	out[o] = 0;
	if (o + 1 > size)
		return;
	memcpy(line, out, o + 1);
}

int
readmail(struct queue *queue, int nodot, int recp_from_header)
{
	struct parse_state parse_state;
	char line[1000];	/* by RFC2822 */
	size_t linelen;
	size_t error;
	int had_headers = 0;
	int had_from = 0;
	int had_messagid = 0;
	int had_date = 0;
	int had_first_line = 0;
	int had_last_line = 0;
	int nocopy = 0;

	parse_state.state = NONE;

	error = fprintf(queue->mailf,
		"Received: from %s (uid %d)\n"
		"\t(envelope-from %s)\n"
		"\tid %s\n"
		"\tby %s (%s on %s);\n"
		"\t%s\n",
		username, useruid,
		queue->sender,
		queue->id,
		hostname(), VERSION, systemhostname(),
		rfc822date());
	if ((ssize_t)error < 0)
		return (-1);

	while (!feof(stdin)) {
		if (fgets(line, sizeof(line) - 1, stdin) == NULL)
			break;
		if (had_last_line)
			errlogx(EX_DATAERR, "bad mail input format:"
				" from %s (uid %d) (envelope-from %s)",
				username, useruid, queue->sender);
		linelen = strlen(line);
		if (linelen == 0 || line[linelen - 1] != '\n') {
			/*
			 * This line did not end with a newline character.
			 * If we fix it, it better be the last line of
			 * the file.
			 */
			line[linelen] = '\n';
			line[linelen + 1] = 0;
			had_last_line = 1;
		}
		if (!had_first_line) {
			/*
			 * Ignore a leading RFC-976 From_ or >From_ line mistakenly
			 * inserted by some programs.
			 */
			if (strprefixcmp(line, "From ") == 0 || strprefixcmp(line, ">From ") == 0)
				continue;
			had_first_line = 1;
		}
		if (!had_headers) {
			/*
			 * Unless this is a continuation, switch of
			 * the Bcc: nocopy flag.
			 */
			if (!(line[0] == ' ' || line[0] == '\t'))
				nocopy = 0;

			if (strprefixcmp(line, "Date:") == 0)
				had_date = 1;
			else if (strprefixcmp(line, "Message-Id:") == 0)
				had_messagid = 1;
			else if (strprefixcmp(line, "From:") == 0) {
				had_from = 1;
				if (config.myorigin)
					qualify_from_header(line, sizeof(line),
							    config.myorigin);
			} else if (strprefixcmp(line, "Bcc:") == 0)
				nocopy = 1;

			if (parse_state.state != NONE) {
				if (parse_addrs(&parse_state, line, queue) < 0) {
					errlogx(EX_DATAERR, "invalid address in header\n");
					/* NOTREACHED */
				}
			}

			if (recp_from_header && (
					strprefixcmp(line, "To:") == 0 ||
					strprefixcmp(line, "Cc:") == 0 ||
					strprefixcmp(line, "Bcc:") == 0)) {
				parse_state.state = START;
				if (parse_addrs(&parse_state, line, queue) < 0) {
					errlogx(EX_DATAERR, "invalid address in header\n");
					/* NOTREACHED */
				}
			}
		}

		if (strcmp(line, "\n") == 0 && !had_headers) {
			had_headers = 1;
			while (!had_date || !had_messagid || !had_from) {
				if (!had_date) {
					had_date = 1;
					snprintf(line, sizeof(line), "Date: %s\n", rfc822date());
				} else if (!had_messagid) {
					/* XXX msgid, assign earlier and log? */
					had_messagid = 1;
					snprintf(line, sizeof(line), "Message-Id: <%"PRIxMAX".%s.%"PRIxMAX"@%s>\n",
						 (uintmax_t)time(NULL),
						 queue->id,
						 (uintmax_t)random(),
						 hostname());
				} else if (!had_from) {
					had_from = 1;
					snprintf(line, sizeof(line), "From: <%s>\n", queue->sender);
				}
				if (fwrite(line, strlen(line), 1, queue->mailf) != 1)
					return (-1);
			}
			strcpy(line, "\n");
		}
		if (!nodot && linelen == 2 && line[0] == '.')
			break;
		if (!nocopy) {
			if (fwrite(line, strlen(line), 1, queue->mailf) != 1)
				return (-1);
		}
	}

	return (0);
}
