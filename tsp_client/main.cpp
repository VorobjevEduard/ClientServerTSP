#include <QCryptographicHash>
#include <QFile>
#include <iostream>
#include <cstring>

#include "request.h"
#include "client.h"

void show_help()
{
   std::cout << "Example usage:" << "\n"
       << "tsp --file ""file_to_timestamp"""
       << " --tsa ""tsa_service_address"""
       << " --out ""file_to_save_timestamp"""
       << " [--hash ""sha1 | sha256""]"
       << " [--policy ""policy_oid""]"
       << " [--cert-req]"
       << " [--nonce ""1234567890ABCDEF""]" << "\n";
}

QByteArray fileChecksum(const QString &fileName,
                        QCryptographicHash::Algorithm hashAlgorithm)
{
    QFile f(fileName);
    if (f.open(QFile::ReadOnly)) {
        QCryptographicHash hash(hashAlgorithm);
        if (hash.addData(&f)) {
            return hash.result();
        }
    }
    return QByteArray();
}

int main(int argc, char** argv)
{
   if (argc == 1) {
       show_help();
       return 0;
   }

   QString fileName = "";
   QString tsa = "";
   QString outFile = "";
   QString hash = "";
   QString policy = "";
   QString nonce = "";
   QString cert = "";

   int i = 1;
   while (i < argc) {
       if (strcmp(argv[i], "--file") == 0)
           fileName = argv[++i];
       else if (strcmp(argv[i], "--tsa") == 0)
           tsa = argv[++i];
       else if (strcmp(argv[i], "--out") == 0)
           outFile = argv[++i];
       else if (strcmp(argv[i], "--hash") == 0)
           hash = argv[++i];
       else if (strcmp(argv[i], "--policy") == 0)
           policy = argv[++i];
       else if (strcmp(argv[i], "--cert-req") == 0)
           cert = "true";
       else if (strcmp(argv[i], "--nonce") == 0)
           nonce = argv[++i];
       ++i;
   }

   QString hashed_data;
   if (hash == "sha1") {
       hashed_data = fileChecksum(fileName, QCryptographicHash::Sha1).toHex();
   } else {
       hashed_data = fileChecksum(fileName, QCryptographicHash::Sha256).toHex();
   }

   tsp::Request* request = new
       tsp::Request("1", hash, hashed_data, policy, nonce, cert);

   client* Client = new client(tsa, 55555, request, outFile);

   delete Client;
   delete request;
   return 0;
}
