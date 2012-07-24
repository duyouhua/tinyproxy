/* tinyproxy - a fast light-weight http proxy
 * copyright (c) Larry He
 *
 * this program is free software; you can redistribute it and/or modify
 * it under the terms of the gnu general public license as published by
 * the free software foundation; either version 2 of the license, or
 * (at your option) any later version.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license along
 * with this program; if not, write to the free software foundation, inc.,
 * 51 franklin street, fifth floor, boston, ma 02110-1301 usa.
 */

/* See 'autoresp.c' for detailed information. */

#ifndef _TINYPROXY_AUTORESP_H_
#define _TINYPROXY_AUTORESP_H_

extern void autoresp_init (void);
extern void autoresp_destroy (void);
extern void autoresp_reload (void);
extern char *map_to_local_file (const char *url);
#endif
