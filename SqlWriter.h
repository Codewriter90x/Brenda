#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <my_global.h>
#include <mysql.h>

using namespace std;

static MYSQL *conn;
 
int ckSQLConnection()
{
  
  //Connesione al Server MySQL
  conn=mysql_init(NULL);
  if (conn!=NULL) 
  {
    cout << "Connesione Riuscita\n\a";
  }
  else
  {
    cout <<"connesione non riuscita\n";
    return 0;
  }
  
  //Connesione al database
  if (!mysql_real_connect(conn,"127.0.0.1","root","Accesso","Br3nd4",0,NULL,0))
  {
    cout << "Errore nella connesione al database \n";
    
    return 1;    
  }
  else
  {
    cout <<"Connesione al database riuscita\n\a";
  }
  return 0;
}

int AddTcpPacket(char *IpSorgente, char *IpDestinatario,const u_char *Payload, int size_payload,string ports)
{
  string pacchetto="";
  const u_char *ch;
  ch = Payload;
  int Nspacer= 0;
	    
  for(int i = 0; i < size_payload; i++) //mi serve x formattare il pacchetto a blocchi di 25 caratteri x riga
  {
    if (isprint(*ch))
      pacchetto += *ch;
    else
      pacchetto +=".";
    ch++;
    Nspacer ++;
    if (Nspacer==25)
    {
      Nspacer =0;
      pacchetto+= "\n";
    }

  }
  
  //cout << pacchetto;
  string sql;
        sql ="INSERT INTO TcpPackets (IpSource, IpDest,PayLoad,Port,DateAndTime) VALUES ('";
        sql +=*IpSorgente;
        sql += "','";
	sql +=*IpDestinatario;
	sql += "','";
	sql +=pacchetto;
	sql += "','";
	sql +=ports;
	sql += "','n desso')";

  if (mysql_query(conn, sql.c_str()) == 0) 
  {
    cout << "Record inserito nel Database\n";
  }
  else 
  {
    cout << "Impossibile inserire record nel db\n";
  }
  
  mysql_close(conn);
  
  return 0; 
  
}



