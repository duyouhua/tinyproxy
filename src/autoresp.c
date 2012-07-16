/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) Larry He
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "main.h"

#include "autoresp.h"
#include "heap.h"
#include "log.h"
#include "reqs.h"
#include "conf.h"

#define LINE_BUFFER_LEN (512)
#define RULES_PAT "^[[:space:]]*([^\"]+)[[:space:]]+\"([^\"]+)\"[[:space:]]*$"
static int err;

struct autoresponder_rule_list {
        struct autoresponder_rule_list *next;
        regex_t *regx;
        char *path_pat;
        char *local_file_pat;
};

static struct autoresponder_rule_list *rule_list = NULL;
static int already_init = 0;
static regex_t rule_pt;

static char *sub_string(const char *line, regmatch_t m){
        char *p;
        const unsigned int len = m.rm_eo - m.rm_so;
        assert (line);
        assert (len > 0);

        p = (char *) safemalloc (len + 1);
        if (!p)
                return NULL;
        memcpy (p, line + m.rm_so, len);
        p[len] = '\0';
        return p;
}
/*
 * Initializes a linked list of strings containing path and local file pattern pairs
 */
void autoresp_init (void)
{
        FILE *fd;
        char buf[LINE_BUFFER_LEN];

        log_message (LOG_INFO, "init auto responder rule list");
        if (rule_list || already_init) {
            log_message (LOG_INFO, "autoresponder rule list was already active");
            return;
        }

        err = regcomp(& rule_pt, RULES_PAT, REG_EXTENDED | REG_ICASE | REG_NEWLINE);

        if (err != 0) {
                fprintf (stderr, "bad regex in %s\n", RULES_PAT);
                exit (EX_DATAERR);
        }

        fd = fopen (config.autoresponder_rules, "r");
        if (!fd) {
            log_message (LOG_INFO, "error in opening file %s", config.autoresponder_rules);
            return;
        }

        while (fgets (buf, LINE_BUFFER_LEN, fd)) {
            check_match(buf);
        }
        if (ferror (fd)) {
                perror ("fgets");
                exit (EX_DATAERR);
        }
        fclose (fd);

        already_init = 1;
}

int check_match (const char *line)
{
        struct autoresponder_rule_list *p;
        regmatch_t match[3];
        p = NULL;
        if (!regexec (& rule_pt, line, 3, match, 0)){
            if (!p) /* head of list */
                    rule_list = p =
                        (struct autoresponder_rule_list *)
                        safecalloc (1, sizeof (struct autoresponder_rule_list));
            else {  /* next entry */
                    p->next =
                        (struct autoresponder_rule_list *)
                        safecalloc (1, sizeof (struct autoresponder_rule_list));
                    p = p->next;
            }
            p->path_pat = sub_string (line,match[1]);
            p->local_file_pat = sub_string (line,match[2]);
            p->regx = (regex_t *) safemalloc (sizeof (regex_t));
            log_message (LOG_INFO, "path pattern %s corresponds to %s", p->path_pat, p->local_file_pat);
            err = regcomp(p->regx, p->path_pat, REG_EXTENDED | REG_ICASE | REG_NEWLINE);
            if (err != 0) {
                    fprintf (stderr, "bad regex in %s\n", p->path_pat);
                    exit (EX_DATAERR);
            }
            return 0;
        }
        return -1;
}


/* unlink the list */
void autoresp_destroy (void)
{
        struct autoresponder_rule_list *p, *q;

        if (already_init) {
                for (p = q = rule_list; p; p = q) {
                        regfree (p->regx);
                        safefree (p->regx);
                        safefree (p->path_pat);
                        safefree (p->local_file_pat);
                        q = p->next;
                        safefree (p);
                }
                rule_list = NULL;
                already_init = 0;
        }
}

/**
 * reload the autoresponder_rules file if autoresponder is enabled
 */
void autoresp_reload (void)
{
        if (config.autoresponder_rules) {
                log_message (LOG_NOTICE, "Re-reading autoresponder_rules file.");
                autoresp_destroy ();
                autoresp_init ();
        }
}


/* returns 0 to allow, non-zero to block */
char *map_to_local_file (const char *url)
{
        struct autoresponder_rule_list *p;
        int result;

        if (!rule_list || !already_init)
                goto COMMON_EXIT;

        for (p = rule_list; p; p = p->next) {
                result =
                    regexec (p->regx, url, (size_t) 0, (regmatch_t *) 0, 0);

                if (result == 0) {
                    return p->local_file_pat;
                }else{
                    return 0;
                }
        }

COMMON_EXIT:
                return 0;
}
