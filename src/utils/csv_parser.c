/*
 * VaultC — RFC 4180 CSV Parser
 * File: src/utils/csv_parser.c
 */

#include "vaultc/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Opaque parser structure ───────────────────────────────────────────────── */

struct CsvParser
{
    FILE *fp;
    char *line_buf;     /* Dynamic line buffer                */
    size_t line_cap;    /* Capacity of line_buf               */
    size_t line_len;    /* Current length of data in line_buf */
    int eof;            /* Set when feof is reached           */
};

/* ── Internal: read a complete logical line (handles \r\n and \n) ──────────── */

static int read_raw_line(CsvParser *p)
{
    p->line_len = 0;

    if (p->eof)
    {
        return 0;
    }

    for (;;)
    {
        int ch = fgetc(p->fp);
        if (ch == EOF)
        {
            p->eof = 1;
            return p->line_len > 0 ? 1 : 0;
        }

        /* Grow buffer if needed */
        if (p->line_len + 2 > p->line_cap)
        {
            p->line_cap = p->line_cap == 0 ? 256 : p->line_cap * 2;
            char *tmp = realloc(p->line_buf, p->line_cap);
            if (tmp == NULL)
            {
                return -1;
            }
            p->line_buf = tmp;
        }

        if (ch == '\n')
        {
            /* Strip trailing \r if present (CRLF → LF) */
            if (p->line_len > 0 && p->line_buf[p->line_len - 1] == '\r')
            {
                p->line_len--;
            }
            p->line_buf[p->line_len] = '\0';
            return 1;
        }

        p->line_buf[p->line_len++] = (char)ch;
    }
}

/* ── Internal: read a complete CSV record (may span multiple raw lines
 *    if a quoted field contains newlines) ───────────────────────────────────── */

static int read_csv_record(CsvParser *p)
{
    /* Read the first raw line */
    int rc = read_raw_line(p);
    if (rc <= 0)
    {
        return rc;
    }

    /* Check if we have an unmatched quote — means the record spans lines */
    for (;;)
    {
        int in_quotes = 0;
        for (size_t i = 0; i < p->line_len; i++)
        {
            if (p->line_buf[i] == '"')
            {
                in_quotes = !in_quotes;
            }
        }

        if (!in_quotes)
        {
            /* All quotes are matched, record is complete */
            break;
        }

        /* Need to read another raw line and append with \n */
        if (p->eof)
        {
            break; /* Unterminated quote at EOF — return what we have */
        }

        /* Append a newline character to the buffer */
        if (p->line_len + 2 > p->line_cap)
        {
            p->line_cap *= 2;
            char *tmp = realloc(p->line_buf, p->line_cap);
            if (tmp == NULL)
            {
                return -1;
            }
            p->line_buf = tmp;
        }
        p->line_buf[p->line_len++] = '\n';

        /* Read next raw line into a temporary position */
        size_t saved_len = p->line_len;
        size_t saved_cap = p->line_cap;

        /* We need to read more data and append to the existing buffer */
        for (;;)
        {
            int ch = fgetc(p->fp);
            if (ch == EOF)
            {
                p->eof = 1;
                break;
            }

            if (p->line_len + 2 > p->line_cap)
            {
                p->line_cap = p->line_cap * 2;
                char *tmp2 = realloc(p->line_buf, p->line_cap);
                if (tmp2 == NULL)
                {
                    return -1;
                }
                p->line_buf = tmp2;
            }

            if (ch == '\n')
            {
                if (p->line_len > saved_len &&
                    p->line_buf[p->line_len - 1] == '\r')
                {
                    p->line_len--;
                }
                break;
            }

            p->line_buf[p->line_len++] = (char)ch;
        }

        p->line_buf[p->line_len] = '\0';
        (void)saved_cap;
    }

    p->line_buf[p->line_len] = '\0';
    return 1;
}

/* ── Internal: parse a single field from position *pos in record ───────────── */

static char *parse_field(const char *rec, size_t rec_len, size_t *pos)
{
    size_t start = *pos;

    if (start >= rec_len)
    {
        /* Empty trailing field */
        char *empty = malloc(1);
        if (empty == NULL)
        {
            return NULL;
        }
        empty[0] = '\0';
        return empty;
    }

    if (rec[start] == '"')
    {
        /* Quoted field */
        start++;
        size_t cap = 64;
        size_t len = 0;
        char *field = malloc(cap);
        if (field == NULL)
        {
            return NULL;
        }

        size_t i = start;
        while (i < rec_len)
        {
            if (rec[i] == '"')
            {
                if (i + 1 < rec_len && rec[i + 1] == '"')
                {
                    /* Escaped quote: "" → " */
                    if (len + 1 >= cap)
                    {
                        cap *= 2;
                        char *tmp = realloc(field, cap);
                        if (tmp == NULL)
                        {
                            free(field);
                            return NULL;
                        }
                        field = tmp;
                    }
                    field[len++] = '"';
                    i += 2;
                }
                else
                {
                    /* End of quoted field */
                    i++; /* skip closing quote */
                    break;
                }
            }
            else
            {
                if (len + 1 >= cap)
                {
                    cap *= 2;
                    char *tmp = realloc(field, cap);
                    if (tmp == NULL)
                    {
                        free(field);
                        return NULL;
                    }
                    field = tmp;
                }
                field[len++] = rec[i++];
            }
        }

        field[len] = '\0';

        /* Skip comma after closing quote (or we're at end) */
        if (i < rec_len && rec[i] == ',')
        {
            i++;
        }
        *pos = i;
        return field;
    }
    else
    {
        /* Unquoted field — read until comma or end */
        size_t end = start;
        while (end < rec_len && rec[end] != ',')
        {
            end++;
        }

        size_t flen = end - start;
        char *field = malloc(flen + 1);
        if (field == NULL)
        {
            return NULL;
        }
        memcpy(field, rec + start, flen);
        field[flen] = '\0';

        *pos = (end < rec_len) ? end + 1 : end;
        return field;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

CsvParser *csv_open(const char *path)
{
    if (path == NULL)
    {
        return NULL;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
    {
        return NULL;
    }

    CsvParser *p = calloc(1, sizeof(CsvParser));
    if (p == NULL)
    {
        fclose(fp);
        return NULL;
    }

    p->fp = fp;
    p->line_buf = NULL;
    p->line_cap = 0;
    p->line_len = 0;
    p->eof = 0;

    return p;
}

int csv_read_row(CsvParser *p, char ***fields_out, int *count_out)
{
    if (p == NULL || fields_out == NULL || count_out == NULL)
    {
        return -1;
    }

    *fields_out = NULL;
    *count_out = 0;

    int rc = read_csv_record(p);
    if (rc <= 0)
    {
        return rc;
    }

    /* Parse fields from the record buffer */
    int capacity = 16;
    char **fields = malloc((size_t)capacity * sizeof(char *));
    if (fields == NULL)
    {
        return -1;
    }
    int count = 0;

    size_t pos = 0;
    size_t rec_len = p->line_len;

    /* Handle empty record (produces one empty field) */
    do
    {
        if (count >= capacity)
        {
            capacity *= 2;
            char **tmp = realloc(fields, (size_t)capacity * sizeof(char *));
            if (tmp == NULL)
            {
                for (int i = 0; i < count; i++)
                {
                    free(fields[i]);
                }
                free(fields);
                return -1;
            }
            fields = tmp;
        }

        char *field = parse_field(p->line_buf, rec_len, &pos);
        if (field == NULL)
        {
            for (int i = 0; i < count; i++)
            {
                free(fields[i]);
            }
            free(fields);
            return -1;
        }
        fields[count++] = field;
    } while (pos < rec_len);

    *fields_out = fields;
    *count_out = count;
    return 1;
}

void csv_close(CsvParser *p)
{
    if (p == NULL)
    {
        return;
    }

    if (p->fp != NULL)
    {
        fclose(p->fp);
    }
    free(p->line_buf);
    free(p);
}
