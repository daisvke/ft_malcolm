#include "ft_malcolm.h"

size_t	_mc_strlen(const char *s)
{
	size_t	i;

	i = 0;
	while (s[i])
		i++;
	return (i);
}

void	_mc_bzero(void *s, size_t n)
{
	char	*str;

	str = s;
	while (n--)
		*str++ = 0;
}

int	_mc_strncmp(const char *s1, const char *s2, size_t n)
{
	while ((*s1 || *s2) && n--)
	{
		if (*s1 != *s2)
			return ((unsigned char)(*s1) - (unsigned char)(*s2));
		s1++;
		s2++;
	}
	return (0);
}

int	_mc_memcmp(const void *p1, const void *p2, size_t n)
{
	unsigned char	*s1;
	unsigned char	*s2;

	s1 = (unsigned char *)p1;
	s2 = (unsigned char *)p2;
	while (n--)
	{
		if (*s1 != *s2)
			return ((unsigned char)(*s1) - (unsigned char)(*s2));
		s1++;
		s2++;
	}
	return (0);
}

void	*_mc_memcpy(void *dest, const void *src, size_t n)
{
	char		*d;
	const char	*s;

	d = dest;
	s = src;
	if (!dest && !src)
		return (NULL);
	while (n--)
		*d++ = *s++;
	return (dest);
}

int	_mc_tolower(int c)
{
	if (c >= 'A' && c <= 'Z')
		return (c + 32);
	return (c);
}

int	_mc_isdigit(int c)
{
	return (c >= '0' && c <= '9');
}

int	_mc_isxdigit(int c)
{
	return (_mc_isdigit(c) || (_mc_tolower(c) >= 'a' && _mc_tolower(c) <= 'f'));
}
