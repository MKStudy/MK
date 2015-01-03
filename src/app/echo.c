/*
 * echo.c
 *
 *  Created on: 2014年12月11日
 *      Author: zxb
 */

int	printx(char* str);
char szText[] = "global data!\n";
int main(int argc, char* argv[])
{
	static char szStaticText[] = "static data\n";
	printx("echo run!\n");
	printx(szText);
	printx(szStaticText);
	return 0;
}



