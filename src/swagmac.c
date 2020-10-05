/*
 ============================================================================
 Name        : swagmac.c
 Author      : John Kuras
 Version     :
 Copyright   : free
 Description : id SWAG computers via mac address in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifdef WINDOZE
#define ssize_t int
ssize_t getline(char** lineptr, size_t* n, FILE* stream)
{
	if ( fgets(*lineptr, (int)n, stream) == NULL ) return(-1);
	return strlen( *lineptr);
}
#endif

#define LINELEN	250
#define NUMCOMP 600
#define NUMOUI 60000
#define LINELENp5	LINELEN + 5
#define NUMPORTS	24
#define SWDATAFMT	0

typedef struct compdata
{
	unsigned long long           MAC;
	unsigned long           	 IP;
	int						     PortNumber;
	char *						 Name;
	char *						 Vendor;
	char *						 User;
	char *						 FirstSeen;
	char *						 LastSeen;
} CompDbStructure;
int numcomps = 0;

CompDbStructure * compdb;
CompDbStructure compt;

typedef struct ouidata
{
	unsigned long long           MAC;
	unsigned long long           Mask;
	char *						 ShortName;
	char *						 LongName;
} OuiDbStructure;
int numoui = 0;

OuiDbStructure * ouidb;
OuiDbStructure oui;

void trimleadingandTrailing(char *s);
int parsline(char *line,char *tname,char *tip,char *tmac);
int findmac(unsigned long long tmacll);
unsigned long ipstr2l(char *tip);
int macstr2ll(char *tmac, unsigned long long *tmacll, unsigned long long *tmaskll, int format);
void printcomp(CompDbStructure* compdata, FILE *fp2);
void printoui(OuiDbStructure* ouidata, FILE *fp2);
void printmac(unsigned long long MAC, FILE *fp2);
void sprintmac(unsigned long long MAC, char *buff);
void printip(unsigned long IP, FILE *fp2);
void sprintip(unsigned long IP, char *buff);
unsigned short getbytell(unsigned long long MAC, int i);
unsigned short getbytel(unsigned long IP, int i);
int parsline2(char *line,char *tmac,char *tport);
int nextsp ( char * line, int searchType);
int portstr2int(char * tport,int * port);
void parseScan (xmlDocPtr doc, xmlNodePtr cur, int *numnew, FILE *fp2);
int parsline3(char *line,int nlabs,int *colns,char **cdata,char * delims);
int findvendor(unsigned long long MAC,char * tven);
int compareMACpref(unsigned long long MAC,OuiDbStructure *oui);
int loadmacdata(xmlDocPtr macdoc, FILE *fp2);
int savemacdata(xmlDocPtr macdoc);

xmlDocPtr macdoc;
xmlNodePtr maccur;
xmlNodePtr macroot;




int main(int argc, char* argv[])
{
	FILE *fp;
	FILE *fp2;
	char * line = NULL;
	size_t len = LINELEN;
	ssize_t read;
	size_t size = LINELENp5;
//	char * redir;
//	char redir1[] = ">";
//	char redir2[] = ">>";
	int first = 0;
	int second = 0;
	int third = 0;
	int fourth = 0;
	int fifth = 0;
	int sixth = 0;
	char *filename;
	char *switchfile;
	char tname[LINELEN];
	char tven[LINELEN];
	char tip[LINELEN];
	char tmac[LINELEN];
	char tport[LINELEN];
	char * ttname;
	char * ttven;
	int linenum = 0;
	unsigned long long tmacll;
	unsigned long long tmaskll;
	unsigned long tipl;
	int i;
	int icomp;
	int port;

	if (argc > 1) {
		if ((strcmp(argv[1], "all") == 0) | (strcmp(argv[1], "first") == 0)) first = 1;
		if ((strcmp(argv[1], "all") == 0) | (strcmp(argv[1], "second") == 0)) second = 1;
		if ((strcmp(argv[1], "all") == 0) | (strcmp(argv[1], "third") == 0)) third = 1;
		if ((strcmp(argv[1], "all") == 0) | (strcmp(argv[1], "fourth") == 0)) fourth = 1;
		if ((strcmp(argv[1], "all") == 0) | (strcmp(argv[1], "fifth") == 0)) fifth = 1;
		if ((strcmp(argv[1], "all") == 0) | (strcmp(argv[1], "sixth") == 0)) sixth = 1;
	}
	else {
		first = 1;
		second = 1;
		third = 1;
		fourth = 1;
		fifth = 1;
		sixth = 1;
	}
	switchfile = "24portMACs.txt";
	if (argc > 2)  switchfile = argv[2] ;

//	redir = redir1;
	line = (char*)malloc(size);
	compdb = (CompDbStructure*)malloc(sizeof(CompDbStructure)*NUMCOMP);
	ouidb = (OuiDbStructure*)malloc(sizeof(OuiDbStructure)*NUMOUI);

	macdoc = xmlParseFile("MACdata.xml");
	if (macdoc == NULL ) {
			fprintf(stderr,"MACdata document not parsed successfully. \nUnable to open old MAC xml file\n");
		} else {
			printf(" loading old MAC data\n");
			fp2 = fopen("oldmaclist.txt", "w");
			if (fp2 == NULL) return(2);
			loadmacdata(macdoc,fp2);
			xmlFreeDoc(macdoc);
			fclose(fp2);
		}

	if (first) {
		filename = "opsiMACs.csv";
		fp = fopen(filename, "r");
// "andrew.swag.local","student tablet (RCA)",,"2020-03-17 14:45:47","10.0.0.111","0c:9a:42:18:3f:6c"
		if (fp == NULL)return(1);
		printf(" processing %s\n",filename);

		fp2 = fopen("maclist.txt", "w");
		if (fp2 == NULL)return(2);

		int numnew = 0;
		while ((read = getline(&line, &len, fp)) != -1) {
			//	        printf("Retrieved line of length %zu:\n", read);
			line[read - 1] = '\000';
			linenum++;
			fprintf(fp2," line found : \"%s\"\n", line);
			if (parsline(line,tname,tip,tmac) != 0) continue;
			if(strlen(tmac)<17) {
				fprintf(fp2," error : mac address bad on line %i\n",linenum);
				continue;
			}
			if (macstr2ll(tmac,&tmacll,&tmaskll,1)) {
				fprintf(fp2," error : bad mac address format on line %i\n",linenum);
				continue;
			}
			tipl = ipstr2l(tip);
			ttname = (char*)malloc(strlen(tname)+4);
			strcpy(ttname,tname);
			compt.Name = ttname;
			compt.MAC = tmacll;
			compt.IP = tipl;
			compt.PortNumber = -1;
			if ((icomp = findmac(tmacll)) == -1 ) {
				compdb[numcomps] = compt;
				numcomps++;
				numnew++;
				if ( numcomps > NUMCOMP ) {
					printf("error: too many computers found!\n");
					return(3);
				}
			} else {
				fprintf(fp2," warning : MAC address duplicated at line %i. Dup with icomp = %i (\"%s\")\n",linenum,icomp,(compdb+icomp)->Name);
//				compdb[icomp] = compt;
			}

//			if ( strlen(line) > 2 ) fprintf(fp2, "dsquery * %s -scope base -attr objectSid %s studentSIDs.txt\n", line, redir);
//			redir = redir2;
		}
		fclose(fp);
		if (numcomps>0) {
			for (i=0;i<numcomps;i++) {
				printcomp(compdb+i,fp2);
			}
		}
		printf(" %i new MACs found\n",numnew);
		fclose(fp2);
	}

	/*
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE nmaprun>
	<host><status state="up" reason="arp-response" reason_ttl="0"/>
	<address addr="10.0.0.1" addrtype="ipv4"/>
	<address addr="5C:F4:AB:6D:F4:FB" addrtype="mac" vendor="ZyXEL Communications"/>
	<hostnames>
	<hostname name="_gateway" type="PTR"/>
	</hostnames>
	<times srtt="700" rttvar="5000" to="100000"/>
	</host>
*/

	if (second) {
		xmlDocPtr doc;
		xmlNodePtr cur;
		int numnew = 0;
		filename = "scan2X.txt";
		printf(" processing %s\n",filename);

		fp2 = fopen("maclistscan.txt", "w");
		if (fp2 == NULL)return(2);

		doc = xmlParseFile(filename);
		if (doc == NULL ) {
				fprintf(stderr,"Document not parsed successfully. \n");
				return(1);
			}

		cur = xmlDocGetRootElement(doc);

		if (cur == NULL) {
			fprintf(stderr,"empty document\n");
			xmlFreeDoc(doc);
			return(2);
		}

		if (xmlStrcmp(cur->name, (const xmlChar *) "nmaprun")) {
				fprintf(stderr,"document of the wrong type, root node != nmaprun");
				xmlFreeDoc(doc);
				return(3);
		}

		cur = cur->xmlChildrenNode;
		fprintf(fp2,"------------------\n");
		while (cur != NULL) {
			if ((!xmlStrcmp(cur->name, (const xmlChar *)"host"))){
				parseScan (doc, cur, &numnew, fp2);
				fprintf(fp2,"------------------\n");
			}
		cur = cur->next;
		}

		xmlFreeDoc(doc);
		printf(" %i new MACs found\n",numnew);
		fclose(fp2);
	}


	if (third) {
		filename = "unifimac.txt";
		fp = fopen(filename, "r");
//	ica-2007	IntelCor	00:21:6b:eb:c1:2a	-	User	6.75 GB	309 MB	07/30/2020 6:12 pm	09/07/2020 10:15 am
		if (fp == NULL)return(1);
		printf(" processing %s\n",filename);

		fp2 = fopen("maclist3.txt", "w");
		if (fp2 == NULL)return(2);

		int colns[] = {3,1,2};
#define NLABS 3
		int nlabs = NLABS;
		char * cdata[NLABS];
		int numnew = 0;

		for (i=0;i<NLABS;i++) cdata[i] = (char*)malloc(LINELEN);

		linenum = 0;
		while ((read = getline(&line, &len, fp)) != -1) {
			//	        printf("Retrieved line of length %zu:\n", read);
			line[read - 1] = '\000';
			linenum++;
			fprintf(fp2," line found : \"%s\"\n", line);
			if (parsline3(line,nlabs,colns,cdata,(char *)"\t") != 0) continue;
			tmac[0] = '\000';
			tname[0] = '\000';
			tven[0] = '\000';
			if (strlen(cdata[0]) > 0) strcpy(tmac,cdata[0]);
			if (strlen(cdata[1]) > 0) strcpy(tname,cdata[1]);
			if (strlen(cdata[2]) > 0) strcpy(tven,cdata[2]);
			if(strlen(tmac)<17) {
				fprintf(fp2," error : mac address bad on line %i\n",linenum);
				continue;
			}
			if (macstr2ll(tmac,&tmacll,&tmaskll,1)) {
				fprintf(fp2," error : bad mac address format on line %i\n",linenum);
				continue;
			}
//			tipl = ipstr2l(tip);
			ttname = (char*)malloc(strlen(tname)+4);
			ttven = (char*)malloc(strlen(tven)+4);
			strcpy(ttname,tname);
			strcpy(ttven,tven);
			compt.Name = ttname;
			compt.Vendor = ttven;
			compt.MAC = tmacll;
			compt.IP = 0;
			compt.PortNumber = -1;
			if ((icomp = findmac(tmacll)) == -1 ) {
				compdb[numcomps] = compt;
				numcomps++;
				numnew++;
			} else {
				if (strlen(tname) > 0) {
					free((compdb+icomp)->Name);
					(compdb+icomp)->Name = compt.Name;
				} else {
					free(ttname);
				}
				if (strlen(tven) > 0) {
					free((compdb+icomp)->Vendor);
					(compdb+icomp)->Vendor = compt.Vendor;
				} else {
					free(ttven);
				}
//				if (strlen(tip) > 0) (compdb+icomp)->IP = compt.IP;
				fprintf(fp2," warning : MAC address duplicated. Dup with icomp = %i (\"%s\")\n",icomp,(compdb+icomp)->Name);
	//				compdb[icomp] = compt;
			}

//			if ( strlen(line) > 2 ) fprintf(fp2, "dsquery * %s -scope base -attr objectSid %s studentSIDs.txt\n", line, redir);
//			redir = redir2;
		}
		fclose(fp);
		for (i=0;i<NLABS;i++) free(cdata[i]);
		if (numcomps>0) {
			for (i=0;i<numcomps;i++) {
				printcomp(compdb+i,fp2);
			}
		}
		printf(" %i new MACs found\n",numnew);
		fclose(fp2);
	}


	if (fourth) {
		filename = "leases.txt";
		fp = fopen(filename, "r");
//10.0.0.11	DESKTOP-SDRAR14.SWAG.local	9/25/2020 4:53:37 PM	DHCP	d017c28ba606		Full Access	N/A	None
		if (fp == NULL)return(1);
		printf(" processing %s\n",filename);

		fp2 = fopen("maclist4.txt", "w");
		if (fp2 == NULL)return(2);

//		int colns[] = {5,1,0};
		int colns[] = {4,1,0};
#define NLABS2 3
		int nlabs = NLABS2;
		char * cdata[NLABS2];
		int numnew = 0;

		for (i=0;i<nlabs;i++) cdata[i] = (char*)malloc(LINELEN);

		linenum = 0;
		while ((read = getline(&line, &len, fp)) != -1) {
			//	        printf("Retrieved line of length %zu:\n", read);
			line[read - 1] = '\000';
			linenum++;
			fprintf(fp2," line found : \"%s\"\n", line);
//			if (parsline3(line,nlabs,colns,cdata,(char *)"\t") != 0) continue;
			if (parsline3(line,nlabs,colns,cdata,(char *)",") != 0) continue;
			tmac[0] = '\000';
			tname[0] = '\000';
			tip[0] = '\000';
			if (strlen(cdata[0]) > 0) strcpy(tmac,cdata[0]);
			if (strlen(cdata[1]) > 0) strcpy(tname,cdata[1]);
			if (strlen(cdata[2]) > 0) strcpy(tip,cdata[2]);
//			if(strlen(tmac)<17) {
			if(strlen(tmac)<12) {
				fprintf(fp2," error : mac address bad on line %i\n",linenum);
				continue;
			}
			if (macstr2ll(tmac,&tmacll,&tmaskll,3)) {
				fprintf(fp2," error : bad mac address format on line %i\n",linenum);
				continue;
			}
			tipl = ipstr2l(tip);
			ttname = (char*)malloc(strlen(tname)+4);
			strcpy(ttname,tname);
			compt.Name = ttname;
			compt.MAC = tmacll;
			compt.IP = tipl;
			compt.PortNumber = -1;
			if ((icomp = findmac(tmacll)) == -1 ) {
				compdb[numcomps] = compt;
				numcomps++;
				numnew++;
			} else {
				if (strlen(tname) > 0) {
					free((compdb+icomp)->Name);
					(compdb+icomp)->Name = compt.Name;
				} else {
					free(ttname);
				}
				if (strlen(tip) > 0) (compdb+icomp)->IP = compt.IP;
				fprintf(fp2," warning : MAC address duplicated. Dup with icomp = %i (\"%s\")\n",icomp,(compdb+icomp)->Name);
	//				compdb[icomp] = compt;
			}

//			if ( strlen(line) > 2 ) fprintf(fp2, "dsquery * %s -scope base -attr objectSid %s studentSIDs.txt\n", line, redir);
//			redir = redir2;
		}
		fclose(fp);
		for (i=0;i<nlabs;i++) free(cdata[i]);
		if (numcomps>0) {
			for (i=0;i<numcomps;i++) {
				printcomp(compdb+i,fp2);
			}
		}
		printf(" %i new MACs found\n",numnew);
		fclose(fp2);
	}

	if (fifth) {
// load oui database
		filename = "oui.txt";
		fp = fopen(filename, "r");
//00:00:01	Xerox	Xerox Corporation
		if (fp == NULL)return(1);
		printf(" processing %s\n",filename);

		fp2 = fopen("ouilist.txt", "w");
		if (fp2 == NULL)return(2);

		int colns[] = {0,1,2};
#define NLABS3 3
		int nlabs = NLABS3;
		char * cdata[NLABS3];

		for (i=0;i<nlabs;i++) cdata[i] = (char*)malloc(LINELEN);

		linenum = 0;
		while ((read = getline(&line, &len, fp)) != -1) {
			//	        printf("Retrieved line of length %zu:\n", read);
			line[read - 1] = '\000';
			linenum++;
			fprintf(fp2," line found : \"%s\"\n", line);
			if (line[0] == '#' ) continue;
			if (parsline3(line,nlabs,colns,cdata,(char *)"\t") != 0) continue;
			tmac[0] = '\000';
			tname[0] = '\000';
			tven[0] = '\000';
			if (strlen(cdata[0]) > 0) strcpy(tmac,cdata[0]);
			if (strlen(cdata[1]) > 0) strcpy(tname,cdata[1]);
			if (strlen(cdata[2]) > 0) strcpy(tven,cdata[2]);
			if(strlen(tmac)<8) {
				fprintf(fp2," error : mac address bad on line %i\n",linenum);
				continue;
			}
			if (macstr2ll(tmac,&tmacll,&tmaskll,1)) {
				fprintf(fp2," error : bad mac address format on line %i\n",linenum);
				continue;
			}
			ttname = (char*)malloc(strlen(tname)+4);
			ttven = (char*)malloc(strlen(tven)+4);
			strcpy(ttname,tname);
			strcpy(ttven,tven);
			oui.ShortName = ttname;
			oui.LongName = ttven;
			oui.MAC = tmacll;
			oui.Mask = tmaskll;
			ouidb[numoui] = oui;
			numoui++;
			if (numoui > NUMOUI) {
				printf("too many oui entries!\n");
				return(4);
			}
		}
		fclose(fp);
		for (i=0;i<nlabs;i++) free(cdata[i]);
		if (numoui>0) {
			for (i=0;i<numoui;i++) {
				printoui(ouidb+i,fp2);
			}
		}
		printf(" %i OUIs found\n",numoui);
		fclose(fp2);
	}

// loop through all computers and fill in all missing vendor names
	int numfound = 0;
	int ifound;
	char bogus[] = "bogus";
	if (numcomps>0) {
		for (i=0;i<numcomps;i++) {
			if ( (compdb+i)->Vendor == NULL) {
				tven[0] = '\000';
				if ( (ifound = findvendor((compdb+i)->MAC,tven)) < 0 ) {
					ttven = (char*)malloc(strlen(bogus)+4);
					strcpy(ttven,bogus);
					(compdb+i)->Vendor = ttven;
					numfound++;
					continue;
				}
				if (strlen(tven)>0) {
					ttven = (char*)malloc(strlen(tven)+4);
					strcpy(ttven,tven);
					(compdb+i)->Vendor = ttven;
					numfound++;
				}
			}
			if ( strlen((compdb+i)->Vendor) == 0) {
				free((compdb+i)->Vendor);
				tven[0] = '\000';
				if ( (ifound = findvendor((compdb+i)->MAC,tven)) < 0 ) {
					ttven = (char*)malloc(strlen(bogus)+4);
					strcpy(ttven,bogus);
					(compdb+i)->Vendor = ttven;
					numfound++;
					continue;
				}
				if (strlen(tven)>0) {
					ttven = (char*)malloc(strlen(tven)+4);
					strcpy(ttven,tven);
					(compdb+i)->Vendor = ttven;
					numfound++;
					continue;
				}
			}
		}
	}
	printf(" %i more vendors identified\n",numfound);



	if (sixth) {
		filename = switchfile;
		fp = fopen(filename, "r");
//00-12-3F-B3-66-DC	1	20	Dynamic	Aging
		if (fp == NULL)return(1);
		printf(" processing %s\n",filename);

		fp2 = fopen("portlist.txt", "w");
		if (fp2 == NULL)return(2);

		linenum = 0;
		while ((read = getline(&line, &len, fp)) != -1) {
			//	        printf("Retrieved line of length %zu:\n", read);
			line[read - 1] = '\000';
			linenum++;
			fprintf(fp2," line found : \"%s\"\n", line);
			if (parsline2(line,tmac,tport) != 0) continue;
			if(strlen(tmac)<17) {
				fprintf(fp2," error : mac address bad on line %i\n",linenum);
				continue;
			}
			if (macstr2ll(tmac,&tmacll,&tmaskll,2)) {
				fprintf(fp2," error : bad mac address format on line %i\n",linenum);
				continue;
			}
			if (portstr2int(tport,&port)) {
				fprintf(fp2," error : bad port format on line %i\n",linenum);
				continue;
			}
			if ((icomp = findmac(tmacll)) == -1 ) {
				tven[0] = '\000';
				if ( findvendor(tmacll,tven) < 0 ) {
					fprintf(fp2," warning : MAC address connected to port %i at line %i not in database. It's vendor is bogus\n",port,linenum);
				} else {
					fprintf(fp2," warning : MAC address connected to port %i at line %i not in database. It's vendor is %s\n",port,linenum,tven);
				}
			} else {
				if ( compdb[icomp].PortNumber > 0 ) {
					fprintf(fp2," warning : MAC address found at multiple ports (%i at line %i, %i in database).\n",port,linenum,compdb[icomp].PortNumber);
				}
				compdb[icomp].PortNumber = port;
			}
		}
		fclose(fp);
		if (numcomps>0) {
			for (i=0;i<NUMPORTS;i++) {
				for (int j=0;j<numcomps;j++) {
					if ( compdb[j].PortNumber == i ) printcomp(compdb+j,fp2);
				}
			}
		}
		fclose(fp2);
	}

	macdoc = xmlNewDoc(BAD_CAST "1.0");
	macroot = xmlNewNode(NULL, BAD_CAST "nmaprun");
	xmlDocSetRootElement(macdoc, macroot);
//	macdoc = xmlParseFile("MACdata.xml");
	savemacdata(macdoc);
// Dumping MAC data to output file
	xmlSaveFormatFileEnc("MACdataOut.xml", macdoc, "UTF-8", 1);
//free the document
	xmlFreeDoc(macdoc);
//Free the global variables that may
//have been allocated by the parser.
	xmlCleanupParser();
// this is to debug memory for regression tests
//	    xmlMemoryDump();

	if ( numcomps>0) {
		for (i=0;i<numcomps;i++) {
			if ( compdb[i].Name != NULL ) {
//				printf("freeing %s\n",compdb[i].Name);
				free(compdb[i].Name);
			} else {
				printf("NULL name at i = %i\n",i);
			}
		}
	}
	free(compdb);
	free(ouidb);
	if (second) puts("!!!Done!!");
	return EXIT_SUCCESS;
}


void trimleadingandTrailing(char *s)
{
	int  i,j;

	for(i=0;s[i]==' '||s[i]=='\t';i++);

	for(j=0;s[i];i++)
	{
		s[j++]=s[i];
	}
	s[j]='\0';
	for(i=0;s[i]!='\0';i++)
	{
		if(s[i]!=' '&& s[i]!='\t')
				j=i;
	}
	s[j+1]='\0';
}

int parsline(char *line,char *tname,char *tip,char *tmac) {
	// "andrew.swag.local","student tablet (RCA)",,"2020-03-17 14:45:47","10.0.0.111","0c:9a:42:18:3f:6c"
	char * delim1 = NULL;
	char * delim2 = NULL;
	*tname = '\000';
	int namelen = 0;
	int iplen = 0;
	int maclen = 0;
	if ( line[0] != ',' ) {
		if ( (delim2 = strstr(line,"\",")) != NULL ) {
			namelen = (delim2 - line);
			strncpy(tname,line+1,namelen-1);
			tname[namelen-1] = '\000';
		}
	}
	tip[0] = '\000';
	if (delim2 == NULL ) delim2 = line+namelen;
	if ( (delim1 = strstr(delim2,",\"10.")) != NULL ) {
		if ( (delim2 = strstr(delim1,"\",")) != NULL ) {
			iplen = (delim2 - delim1);
			strncpy(tip,delim1+2,iplen-2);
			tip[iplen-2] = '\000';
		}
	}
	*tmac = '\000';
	if (delim2 == NULL ) return(-1);
	if (delim1 == NULL ) return(-2);
	if ( (delim1 = strstr(delim2,",\"")) != NULL ) {
		if ( (delim2 = strstr(delim1+2,"\"")) != NULL ) {
			maclen = (delim2 - delim1);
			strncpy(tmac,delim1+2,maclen-2);
		}
	}

	return(0);
}

int findmac(unsigned long long tmacll) {
	if ( numcomps == 0 ) return(-1);
	for (int i=0;i<numcomps;i++) {
		if (compdb[i].MAC == tmacll ) return(i);
	}
	return(-1);
}

unsigned long ipstr2l(char *tip) {
	unsigned int b[4];
	unsigned long ip;
	if (strlen(tip) < 7 ) return (0);
	if ( sscanf(tip,"%u.%u.%u.%u",&b[3],&b[2],&b[1],&b[0]) != 4 ) return (0);
	ip = b[3];
	for (int i=2;i>-1;i--) ip = (ip<<8)+b[i];
	return(ip);
}

int macstr2ll(char *tmac, unsigned long long *tmacll, unsigned long long *tmaskll, int format) {
	unsigned int b[] = {0,0,0,0,0,0};
	int masksize;
	if (tmac[2] == ':' ) format = 1;
	if (tmac[2] == '-' ) format = 2;
	if (strlen(tmac) == 12 ) {
		if ( format == 1 ) {
			return(-1);
		} else if ( format == 2 ) {
			return(-2);;
		} else {
			if ( sscanf(tmac,"%12llx",tmacll) != 1 ) return (-15);
		}
		*tmaskll = 0xffffffffffff;
		return(0);
	}else if (strlen(tmac) == 17 ) {
		if ( format == 1 ) {
			if ( sscanf(tmac,"%2x:%2x:%2x:%2x:%2x:%2x",&b[5],&b[4],&b[3],&b[2],&b[1],&b[0]) != 6 ) return (-3);
		} else if ( format == 2 ) {
			if ( sscanf(tmac,"%2x-%2x-%2x-%2x-%2x-%2x",&b[5],&b[4],&b[3],&b[2],&b[1],&b[0]) != 6 ) return (-4);
		} else {
			return(-5);
		}
		*tmaskll = 0xffffffffffff;
	}else if (strlen(tmac) == 8 ) {
		if ( format == 1 ) {
			if ( sscanf(tmac,"%2x:%2x:%2x",&b[5],&b[4],&b[3]) != 3 ) return (-6);
		} else if ( format == 2 ) {
			if ( sscanf(tmac,"%2x-%2x-%2x",&b[5],&b[4],&b[3]) != 3 ) return (-7);
		} else {
			return(-8);
		}
		*tmaskll = 0xffffff000000;
	}else if (strchr(tmac,'/') == NULL) {
		return (-9);
	} else {
		if ( format == 1 ) {
			if ( sscanf(tmac,"%2x:%2x:%2x:%2x:%2x:%2x/%i",&b[5],&b[4],&b[3],&b[2],&b[1],&b[0],&masksize) != 7 ) return (-10);
		} else if ( format == 2 ) {
			if ( sscanf(tmac,"%2x-%2x-%2x-%2x-%2x-%2x/%i",&b[5],&b[4],&b[3],&b[2],&b[1],&b[0],&masksize) != 7 ) return (-11);
		} else {
			return(-12);
		}
		if ( masksize > 48 ) return (-13);
		if ( masksize < 0 ) return (-14);
		*tmaskll = 0x1;
		for (int i=1;i<masksize;i++) *tmaskll = (*tmaskll<<1)+0x1;
		for (int i=masksize;i<48;i++) *tmaskll = *tmaskll<<1;
	}
	*tmacll = b[5];
	for (int i=4;i>-1;i--) *tmacll = (*tmacll<<8)+b[i];
	return(0);
}

void printcomp(CompDbStructure* compdata, FILE *fp2) {

	//printf("-----------------------\n");
	fprintf(fp2,"-----------------------\n");
	if ( compdata->Name == NULL ) {
		//printf("\"\"\n");
		fprintf(fp2,"\"\"\n");
	} else {
		//printf("\"%s\"\n",compdata->Name);
		fprintf(fp2,"\"%s\"\n",compdata->Name);
	}
	if ( compdata->Vendor == NULL ) {
		//printf("\"\"\n");
		fprintf(fp2,"\"\"\n");
	} else {
		//printf("\"%s\"\n",compdata->Vendor);
		fprintf(fp2,"\"%s\"\n",compdata->Vendor);
	}
	printmac(compdata->MAC,fp2);
	printip(compdata->IP,fp2);
	if ( compdata->PortNumber > -1 ) {
		//printf("Port %i\n",compdata->PortNumber);
		fprintf(fp2,"Port %i\n",compdata->PortNumber);
	}

	return;

}

void printmac(unsigned long long MAC, FILE *fp2) {
	for (int i=5; i>0;i--) {
		//printf("%02x:",getbytell(MAC,i));
		fprintf(fp2,"%02x:",getbytell(MAC,i));
	}
	//printf("%02x\n",getbytell(MAC,0));
	fprintf(fp2,"%02x\n",getbytell(MAC,0));
	return;
}

void sprintmac(unsigned long long MAC, char * buff) {
	char temp[30];
	buff[0] = '\000';
	for (int i=5; i>0;i--) {
		sprintf(temp,"%02x:",getbytell(MAC,i));
		strcat(buff,temp);
	}
	sprintf(temp,"%02x",getbytell(MAC,0));
	strcat(buff,temp);
	return;
}

void printip(unsigned long IP, FILE *fp2) {
	for (int i=3; i>0;i--) {
		//printf("%u.",getbytel(IP,i));
		fprintf(fp2,"%u.",getbytel(IP,i));
	}
	//printf("%u\n",getbytel(IP,0));
	fprintf(fp2,"%u\n",getbytel(IP,0));
	return;
}

void sprintip(unsigned long IP, char *buff) {
	char temp[30];
	buff[0] = '\000';
	for (int i=3; i>0;i--) {
		sprintf(temp,"%u.",getbytel(IP,i));
		strcat(buff,temp);
	}
	sprintf(temp,"%u",getbytel(IP,0));
	strcat(buff,temp);
	return;
}

unsigned short getbytell(unsigned long long MAC, int i) {
	return((MAC>>8*i)&255);
}

unsigned short getbytel(unsigned long IP, int i) {
	return((IP>>8*i)&255);
}

int parsline2(char *line,char *tmac,char * tport) {
	//00-12-3F-B3-66-DC	1	20	Dynamic	Aging ...
	int linelen;
	int nextws = 0;
	int nextnws = 0;
	char * pch;

	linelen = strlen(line);
	if (linelen < 16 ) return (-1);
	*tmac = '\000';
	if ( !isspace(line[0]) ) {
		if ( (nextws = nextsp ( line, 1) ) < 1 ) {
			return (-1);
		}
		if ( nextws > 17 ) return(-2);
		strncpy(tmac,line,nextws);
		tmac[nextws] = '\000';
	}
	if ( (nextnws = nextsp ( line+nextws, 2) ) < 1 ) {
		return (-1);
	}
	nextnws+=nextws;
// now at second field ("1" in above example)
	if ( (nextws = nextsp ( line+nextnws, 1) ) < 1 ) {
		return (-1);
	}
	nextws+=nextnws;
	if ( (nextnws = nextsp ( line+nextws, 2) ) < 1 ) {
		return (-1);
	}
	nextnws+=nextws;
// should now be at third field ("20" in above example)
	if ( (nextws = nextsp ( line+nextnws, 1) ) < 1 ) {
		return (-1);
	}
	tport[0] = '\000';
	strncpy(tport,line+nextnws,nextws);
	tport[nextws] = '\000';
	if ( (pch=strrchr(tport,'/')) != NULL ) {
		strcpy(tport,pch+1);
	}

	return(0);
}

int nextsp ( char * line, int searchType) {
	  char c;
	  int i;
	  int linelen = 0;
	  linelen = strlen(line);
	  if ( linelen == 0 ) return(-1);

	  for (i=0;i<linelen;i++)
	  {
	    c=line[i];
        if ( searchType == 1 ) {
        	if (isspace(c)) return(i);
        } else {
        	if (!isspace(c)) return(i);
        }
	  }
	  return 0;
}

int portstr2int(char * tport,int * port) {

	if (strlen(tport) < 1 ) return (-1);
	if ( sscanf(tport,"%i",port) != 1 ) return (-2);

	return(0);
}

void parseScan (xmlDocPtr doc, xmlNodePtr cur, int *numnew, FILE *fp2) {
	xmlChar *key;
	xmlChar *uri;
	xmlChar *ven;
	xmlNodePtr sub;
	char pnam[LINELEN];
	char pmac[LINELEN];
	char pip[LINELEN];
	char pven[LINELEN];
	pnam[0]='\000';
	pmac[0]='\000';
	pip[0]='\000';
	pven[0]='\000';
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
	    if ((!xmlStrcmp(cur->name, (const xmlChar *)"address"))) {
//		    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
		    uri = xmlGetProp(cur, (const unsigned char *)"addr");
		    key = xmlGetProp(cur, (const unsigned char *)"addrtype");
		    ven = xmlGetProp(cur, (const unsigned char *)"vendor");

		    fprintf(fp2,"addr: %s, ", uri);
		    fprintf(fp2,"addrtype: %s\n", key);
		    if ( ven != NULL ) {
		    	fprintf(fp2,"vendor: %s\n", ven);
		    	strcpy(pven,(char *)ven);
		    	xmlFree(ven);
		    }
		    if (strcmp((char *)key,"mac") == 0) strcpy(pmac,(char *)uri);
		    if (strcmp((char *)key,"ipv4") == 0) strcpy(pip,(char *)uri);
		    xmlFree(uri);
		    xmlFree(key);
 	    }
	    if ((!xmlStrcmp(cur->name, (const xmlChar *)"hostnames"))) {
	    	sub = cur->xmlChildrenNode;
	    	while (sub != NULL) {
	    		if ((!xmlStrcmp(sub->name, (const xmlChar *)"hostname"))) {
	    			uri = xmlGetProp(sub, (const unsigned char *)"name");
	    			fprintf(fp2,"name: %s\n", uri);
	    			strcpy(pnam,(char *)uri);
	    			xmlFree(uri);
	    		}
				sub = sub->next;
	    	}
 	    }
	cur = cur->next;
	}
	if (strlen(pmac) > 0) {
		unsigned long long pmacll;
		unsigned long long tmaskll;
		unsigned long pipl;
		char * ptname;
		char * ptven;
		int picomp;
		if(strlen(pmac)<17) {
			fprintf(fp2," error : mac address bad\n");
			return;
		}
		if (macstr2ll(pmac,&pmacll,&tmaskll,1)) {
			fprintf(fp2," error : bad mac address format\n");
			return;
		}
		pipl = ipstr2l(pip);
		ptname = (char*)malloc(strlen(pnam)+4);
		ptven = (char*)malloc(strlen(pven)+4);
		strcpy(ptname,pnam);
		strcpy(ptven,pven);
		if (strlen(pven) == 0 ) ptven = NULL;
		compt.Name = ptname;
		compt.Vendor = ptven;
		compt.MAC = pmacll;
		compt.IP = pipl;
		compt.PortNumber = -1;
		if ((picomp = findmac(pmacll)) == -1 ) {
			compdb[numcomps] = compt;
			numcomps++;
			(*numnew)++;
		} else {
			if (strlen(pnam) > 0) (compdb+picomp)->Name = compt.Name;
			if (strlen(pven) > 0) (compdb+picomp)->Vendor = compt.Vendor;
			if (strlen(pip) > 0) (compdb+picomp)->IP = compt.IP;
			fprintf(fp2," warning : MAC address duplicated. Dup with icomp = %i (\"%s\")\n",picomp,(compdb+picomp)->Name);
//				compdb[picomp] = compt;
		}
	}
    return;
}

int parsline3(char *line,int nlabs,int *colns,char **cdata,char * delims) {
//	ica-2007	IntelCor	00:21:6b:eb:c1:2a	-	User	6.75 GB	309 MB	07/30/2020 6:12 pm	09/07/2020 10:15 am
// all fields are separated by tabs
// nlabs is the number of fields to process
// colns[] is an array of integer field indecies
// cdata[] is the return array of character strings (each max lenght LINELEN) of parsed output
	char * templine;
	char * pch;
	int i;

	for (i=0;i<nlabs;i++) *(cdata[i]) = '\000';
	if (strlen(line) < 16 ) return (-1);
	templine=strdup(line);

	pch = strsep (&templine,delims);
	int index = 0;
	while (pch != NULL) {
		for (i=0;i<nlabs;i++) {
			if ( colns[i] == index ) {
				strcpy(cdata[i],pch);
			}
		}
	    pch = strsep (&templine, delims);
	    index++;
	}
	free(templine);

	return(0);

}

void printoui(OuiDbStructure* ouidata, FILE *fp2) {

	//printf("-----------------------\n");
	fprintf(fp2,"-----------------------\n");
	printmac(ouidata->MAC,fp2);
	printmac(ouidata->Mask,fp2);
	if ( ouidata->ShortName == NULL ) {
		//printf("\"\"\n");
		fprintf(fp2,"\"\"\n");
	} else {
		//printf("\"%s\"\n",ouidata->ShortName);
		fprintf(fp2,"\"%s\"\n",ouidata->ShortName);
	}
	if ( ouidata->LongName == NULL ) {
		//printf("\"\"\n");
		fprintf(fp2,"\"\"\n");
	} else {
		//printf("\"%s\"\n",ouidata->LongName);
		fprintf(fp2,"\"%s\"\n",ouidata->LongName);
	}

	return;

}

int findvendor(unsigned long long MAC,char * tven) {
	int i;
	for (i=0;i<numoui;i++) {
		if ( compareMACpref(MAC,ouidb+i) ) {
			if (strlen((ouidb+i)->LongName) > 0 ) {
				strcpy(tven,(ouidb+i)->LongName);
				return(0);
			} else {
				if (strlen((ouidb+i)->ShortName) > 0 ) {
					strcpy(tven,(ouidb+i)->ShortName);
					return(0);
				}
			}
		}
	}

	return(-1);
}

int compareMACpref(unsigned long long MAC,OuiDbStructure *oui) {
	if ( (MAC & oui->Mask) == oui->MAC ) return (1);
	return(0);
}

int loadmacdata(xmlDocPtr doc, FILE *fp2){
	xmlNodePtr cur;
	int numnew = 0;

	if (doc == NULL ) {
			fprintf(stderr,"Document not parsed successfully. \n");
			return(1);
		}

	cur = xmlDocGetRootElement(doc);

	if (cur == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(doc);
		return(2);
	}

	if (xmlStrcmp(cur->name, (const xmlChar *) "nmaprun")) {
			fprintf(stderr,"document of the wrong type, root node != nmaprun");
			xmlFreeDoc(doc);
			return(3);
	}

	cur = cur->xmlChildrenNode;
	fprintf(fp2,"------------------\n");
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"host"))){
			parseScan (doc, cur, &numnew, fp2);
			fprintf(fp2,"------------------\n");
		}
	cur = cur->next;
	}

	printf(" %i old MACs found\n",numnew);

	return(0);
}

int savemacdata(xmlDocPtr macdoc) {
	xmlNodePtr cur;
	xmlNodePtr cur2;
	xmlNodePtr node;
	xmlNodePtr root;
//	xmlNodePtr root_node = NULL;/* node pointers */
	int i;
	int numsaved = 0;
	char buff[LINELEN];
/*
<host>
<address addr="10.0.0.2" addrtype="ipv4"/>
<address addr="E8:DE:27:9B:40:40" addrtype="mac" vendor="Tp-link Technologies"/>
<hostnames>
<hostname name="ica-58.swag.local" type="PTR"/>
</hostnames>
</host>
*/
    /*
     * Creates a new document, a node and set it as a root node
     */
//	macdoc = xmlNewDoc(BAD_CAST "1.0");
//    root_node = xmlNewNode(NULL, BAD_CAST "nmaprun");
//    xmlDocSetRootElement(macdoc, root_node);


	if (macdoc == NULL ) {
			fprintf(stderr,"Document not parsed successfully. \n");
			return(1);
		}

	root = xmlDocGetRootElement(macdoc);

	if (root == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(macdoc);
		return(2);
	}

	if (xmlStrcmp(root->name, (const xmlChar *) "nmaprun")) {
			fprintf(stderr,"document of the wrong type, root node != nmaprun");
			xmlFreeDoc(macdoc);
			return(3);
	}

//	cur = cur->xmlChildrenNode;
	if ( numcomps ) {
		for (i = 0; i < numcomps; i++) {
			node = xmlNewChild(root, NULL, BAD_CAST "host", NULL);
			cur = xmlNewChild(node, NULL, BAD_CAST "address", NULL);
			sprintip((compdb+i)->IP, buff);
			xmlNewProp(cur, BAD_CAST "addr", BAD_CAST buff );
			xmlNewProp(cur, BAD_CAST "addrtype", BAD_CAST "ipv4" );

			cur = xmlNewChild(node, NULL, BAD_CAST "address", NULL);
			sprintmac((compdb+i)->MAC, buff);
			xmlNewProp(cur, BAD_CAST "addr", BAD_CAST buff );
			xmlNewProp(cur, BAD_CAST "addrtype", BAD_CAST "mac" );
			xmlNewProp(cur, BAD_CAST "vendor", BAD_CAST (compdb+i)->Vendor );

			cur = xmlNewChild(node, NULL, BAD_CAST "hostnames", NULL);
			cur2 = xmlNewChild(cur, NULL, BAD_CAST "hostname", NULL);
			xmlNewProp(cur2, BAD_CAST "name", BAD_CAST (compdb+i)->Name );
			xmlNewProp(cur2, BAD_CAST "type", BAD_CAST "PTR" );
			numsaved++;
		}
	}

	printf(" %i MACs saved\n",numsaved);

	return(0);
}
