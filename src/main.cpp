#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>


typedef BOOL (WINAPI *PFXISPFXBLOB)(DATA_BLOB *pPFX);
typedef BOOL (WINAPI *PFXVERIFYPASSWORD)(DATA_BLOB *pPFX, LPCWSTR szPassword, DWORD dwFlags);

UINT timerid;
int number;
int oldnum;
int stringsnum=0;
int ctime=0;

VOID CALLBACK tmr(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
     ctime+=2;
     double x=((double)number)/(double)ctime;
     printf("\rPPS: %8.2f; passwords tried: %u (%3.2f%%)",x,number-1,100.0*(double)number/(double)stringsnum);
     oldnum=number;
}

int main(int argc, char *argv[])
{
    SetConsoleTitle("PFX Brute by Kaimi and dx");
    
    
    HANDLE hStdOut=GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("    ____   ______ _  __    ____                __           __\n   / __ \\ / ____/| |/ /   / __ ) _____ __  __ / /_ ___     / /_   __  __\n  / /_/ // /_    |   /   / __  |/ ___// / / // __// _ \\   / __ \\ / / / /\n / ____// __/   /   |   / /_/ // /   / /_/ // /_ /  __/  / /_/ // /_/ /\n/_/    /_/     /_/|_|  /_____//_/    \\__,_/ \\__/ \\___/  /_.___/ \\__, /\n                                                               /____/\n    __ __        _             _                 __\n   / //_/____ _ (_)____ ___   (_)    __     ____/ /_  __\n  / ,<  / __ `// // __ `__ \\ / /  __/ /_   / __  /| |/_/\n / /| |/ /_/ // // / / / / // /  /_  __/  / /_/ /_>  <\n/_/ |_|\\__,_//_//_/ /_/ /_//_/    /_/     \\__,_//_/|_|\n\n");
    SetConsoleTextAttribute(hStdOut, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("                              [ http://kaimi.ru ]\n\n");

    SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

    if(argc<3)
    {
      printf("Usage: pfx.exe pfx_file dict_file\nExample: pfx.exe cert.pfx dict.txt\n");
      return 0;
    }
    
    
    DATA_BLOB pfx = {0, NULL};
    PFXISPFXBLOB PFXIsPFXBlob = NULL;
    PFXVERIFYPASSWORD PFXVerifyPassword = NULL;
    DWORD junk=0;
    
    HMODULE hDLL=LoadLibrary("xpCrypt32.dll");
    if(!hDLL)
    {
          printf("Error: LoadLibrary 0x%X\n",GetLastError());
          return 0;
    }
     
    PFXIsPFXBlob=(PFXISPFXBLOB)GetProcAddress(hDLL,"PFXIsPFXBlob");
    if(!PFXIsPFXBlob)
    {
          FreeLibrary(hDLL);
          printf("Error: GetProcAddress 0x%X\n",GetLastError());
          return 0;
    }
    
    PFXVerifyPassword=(PFXVERIFYPASSWORD)GetProcAddress(hDLL,"PFXVerifyPassword");
    if(!PFXVerifyPassword)
    {
          FreeLibrary(hDLL);
          printf("Error: GetProcAddress 0x%X\n",GetLastError());
          return 0;
    }
    
    printf("Loading PFX...\n");
    HANDLE file = CreateFile(argv[1],GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if(file == INVALID_HANDLE_VALUE)
    {
          FreeLibrary(hDLL);
          printf("Can't open pfx\n");
          return 0;   
    }
    
    pfx.cbData = GetFileSize(file, 0);
    if(!pfx.cbData)
    {
          CloseHandle(file);
          FreeLibrary(hDLL);
          printf("Can't create pfx blob\n");
          return 0;
    }
     
    pfx.pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT,pfx.cbData);
     
    if(!ReadFile(file,pfx.pbData,pfx.cbData,&junk,0))
    {
          printf("Can't read dictionary file\n");
          FreeLibrary(hDLL);
          CloseHandle(file);
          return 0;
    }
    
    junk=0;
    
    CloseHandle(file);

    if(!PFXIsPFXBlob(&pfx))
    {
          FreeLibrary(hDLL);
          printf("Not a pfx file\n");
          return 0;
    }
     
    printf("Loading dictionary...\n");
    file = CreateFile(argv[2],GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if(file == INVALID_HANDLE_VALUE)
    {
          FreeLibrary(hDLL);
          printf("Can't open dictionary\n");
          return 0;   
    }
    
    int size = GetFileSize(file, 0);
    if(size==0)
    {
          printf("The dictionary is empty\n");
          FreeLibrary(hDLL);
          CloseHandle(file);
          return 0;           
    }
               
    void* tempbuf = VirtualAlloc(0,size,MEM_COMMIT,PAGE_READWRITE);
    if(!tempbuf)
    {
          printf("Can't allocate memory\n");
          FreeLibrary(hDLL);
          CloseHandle(file);
          return 0;    
    }
    
    if(!ReadFile(file,tempbuf,size,&junk,0))
    {
          printf("Can't read dictionary file\n");
          FreeLibrary(hDLL);
          VirtualFree(tempbuf,0,MEM_RELEASE);
          CloseHandle(file);
          return 0;
    }
    CloseHandle(file);
    


    number = 1;
    oldnum = 1;
    MSG msg;
    
    char* ptr = new char[512];
    int curr = 0, curr2 = 0;
    char* sym = new char[1];
    
    
    while(true)
    {
        if(size==curr2 || (*sym=*((char*)tempbuf+curr2++))=='\n' || curr==511)
        {   
             stringsnum++;
             curr = 0;
             if(size==curr2)
                  break;   
        }
        else
          *(ptr+curr++) = *sym;
    }
    
    printf("Dictionary loaded. Starting...\n");
    
    timerid=SetTimer(0,0,2000,&tmr);

    
    curr = 0;
    curr2 = 0;
    WCHAR *ptr_u = new WCHAR[512];
                 
                 
    while(true)
    {
        if(size==curr2 || (*sym=*((char*)tempbuf+curr2++))=='\n' || curr==511)
        {    
             if(*(ptr+curr-1)=='\r')
               *(ptr+curr-1) = 0;
             else
               *(ptr+curr) = 0;
               
             curr = 0; 
             number++;

             MultiByteToWideChar(CP_ACP, 0, ptr, -1, ptr_u, 512);
             if(PFXVerifyPassword(&pfx, ptr_u, 0))
             {
                   SetConsoleTextAttribute(hStdOut, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                   printf("\nFound password: %s\n", ptr);
                   SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                   break;                     
             }
             
             if(size==curr2)
             {
                  SetConsoleTextAttribute(hStdOut, FOREGROUND_RED | FOREGROUND_INTENSITY);
                  printf("\nPassword not found :(\n");   
                  SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                  break;   
             }   
             
             if(GetQueueStatus(QS_TIMER))
             {
               GetMessage(&msg, NULL, 0, 0);
               DispatchMessage(&msg);
             }
        }
        else
          *(ptr+curr++) = *sym;
    }
    
    FreeLibrary(hDLL);
    VirtualFree(tempbuf,0,MEM_RELEASE);
    KillTimer(0,timerid);
    
    system("PAUSE");
    return 0;
}