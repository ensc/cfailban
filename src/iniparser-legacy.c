#ifdef NO_iniparser_getsecnkeys
#include "iniparser-legacy.h"

/*-------------------------------------------------------------------------*/
/**
  @brief    Get the number of keys in a section of a dictionary.
  @param    d   Dictionary to examine
  @param    s   Section name of dictionary to examine
  @return   Number of keys in section
 */
/*--------------------------------------------------------------------------*/
int iniparser_getsecnkeys(dictionary * d, char * s)
{
    int     secsize, nkeys ;
    char    *keym;
    int j ;

    nkeys = 0;

    if (d==NULL) return nkeys;
    if (! iniparser_find_entry(d, s)) return nkeys;

    secsize  = (int)strlen(s)+2;
    keym = malloc(secsize);
    snprintf(keym, secsize, "%s:", s);

    for (j=0 ; j<d->size ; j++) {
        if (d->key[j]==NULL)
            continue ;
        if (!strncmp(d->key[j], keym, secsize-1))
            nkeys++;
    }
    free(keym);
    return nkeys;

}

/*-------------------------------------------------------------------------*/
/**
  @brief    Get the number of keys in a section of a dictionary.
  @param    d   Dictionary to examine
  @param    s   Section name of dictionary to examine
  @return   pointer to statically allocated character strings

  This function queries a dictionary and finds all keys in a given section.
  Each pointer in the returned char pointer-to-pointer is pointing to
  a string allocated in the dictionary; do not free or modify them.

  This function returns NULL in case of error.
 */
/*--------------------------------------------------------------------------*/
char ** iniparser_getseckeys(dictionary * d, char * s)
{

    char **keys;

    int i, j ;
    char    *keym;
    int     secsize, nkeys ;

    keys = NULL;

    if (d==NULL) return keys;
    if (! iniparser_find_entry(d, s)) return keys;

    nkeys = iniparser_getsecnkeys(d, s);

    keys = (char**) malloc(nkeys*sizeof(char*));

    secsize  = (int)strlen(s) + 2;
    keym = malloc(secsize);
    snprintf(keym, secsize, "%s:", s);

    i = 0;

    for (j=0 ; j<d->size ; j++) {
        if (d->key[j]==NULL)
            continue ;
        if (!strncmp(d->key[j], keym, secsize-1)) {
            keys[i] = d->key[j];
            i++;
        }
    }
    free(keym);
    return keys;

}

#endif	/* NO_iniparser_getsecnkeys */
