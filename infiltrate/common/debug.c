/*
Copyright 2020 chseasipder

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <string.h>
#include <stdarg.h> 

void _cym_log(char const * format, ...)
{
	static int init = 1;
	FILE *fd = NULL;
	va_list ap;
	
	fd = fopen("LOG.TXT", init ? "w" : "a+");

	if (fd)
	{
		char log_str[1024] = {0};
		init = 0;
		va_start(ap, format);
		vsprintf(log_str, format, ap);
		va_end(ap);
		fprintf(fd, "%s", log_str);
		if (ftell(fd) > 1024 * 1024) /* 暂只记录1M大小日志 */ 
			init = 1;
		fclose(fd);
	}
}
