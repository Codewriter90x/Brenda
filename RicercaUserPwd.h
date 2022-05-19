#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fstream>
#include <vector>

using namespace std;

static vector<string> WordList;

bool ValuableDataContaining(const u_char *Payload, int sizePayload)
{
  int NumPoss=0; 
  string pacchetto="";
  const u_char *ch;
  ch = Payload;
	    
  for(int i = 0; i < sizePayload; i++) //mi serve x formattare il pacchetto a blocchi di 25 caratteri x riga
  {
    if (isprint(*ch))
      pacchetto += *ch;
    else
      pacchetto +=".";
    ch++;

  }
 //cout << pacchetto;
   // cin >> pacchetto;
   
  for(int i=0; i<WordList.size(); i++) // in base alle tot parole creo un loop di tot controlli
  {
    if(strstr(pacchetto.c_str(),WordList.at(i).c_str()) && WordList.at(i)!= "") // controllo se la parola nella posizione del vettore corrente e presente nella stringa
    {
      NumPoss++; // aumento il numero di possibilità
      
    }
    
   
   
  }
  
  if (NumPoss>0)
  {
   return true;
  }
  else
  {
    return false;
  }
}

int getWordList()
{
 ifstream f("WordList.txt");
 string s;

 if(!f) 
 {
  cout<<"Il file non esiste!\n";
  return 1;
 }
 int pChiave=0;

 while(f.good()) //fino a quando c'è qualcosa da leggere ..
 {
  //legge tutta la riga dal file e la mette nella variabile s 
  getline(f, s);
  WordList.push_back(s);
  pChiave++;
 }
 f.close(); //chiude il file
 cout << "Lettura possibili " << pChiave << " parole chiave avvenuta con successo\n";
 return 0; 
}