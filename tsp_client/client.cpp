#include "client.h"
#include "verify.h"

void client::print_to_file(std::ofstream& out, QString answer)
{
    for (; i < answer.length(); ++i) {
        if (answer.toStdString()[i] != ' ')
            out << answer.toStdString()[i];
        else {
            out << "\n";
            ++i;
            break;
        }
    }
}

client::client(const QString& tsa, int nPort,
               tsp::Request* req, QString outFile)
{
    mTcpSocket = new QTcpSocket(this);

    data = (req->get_version() + " " +
        req->get_hash_algorithm() + " " +
        req->get_hashed_message() + " " +
        req->get_req_policy() + " " +
        req->get_nonce() + " " +
        req->get_cert_req() + " " +
        req->get_extensions()).toLocal8Bit();

    mTcpSocket->connectToHost(tsa, 55555);
    if (mTcpSocket->waitForConnected(3000))
    {
        mTcpSocket->waitForReadyRead(3000);
        QByteArray Data = mTcpSocket->readAll();
        std::cout << Data.toStdString() << std::endl;
    }
    mTcpSocket->write(data);
    mTcpSocket->flush();
    mTcpSocket->waitForBytesWritten(3000);
    mTcpSocket->waitForReadyRead(6000);
    QByteArray Data = mTcpSocket->readAll();
    std::cout << "Response received" << std::endl;

    // разделяем полученные данные на две части: подпись, штамп времени
    QString sign = "";
    QString answer = "";
    for (int i = 0; i < Data.length(); ++i) {
        if (Data[i] != '|') {
            sign += Data[i];
        } else {
            for (int j = i + 1; j < Data.length(); ++j) {
                answer += Data[j];
            }
            break;
        }
    }

    // проверка подписи
    init(answer.toStdString().c_str(), sign.toStdString().c_str());

    // если подпись верна, записать штамп времени в файл
    if (status) {
        std::cout << "Writing time-stamp to file " << outFile.toStdString() << std::endl;

        // проверка файла на пустоту
        std::ifstream in(outFile.toStdString(), std::ios::app);
        std::string temp;
        bool file_is_not_empty = true;
        if (in.eof())
            file_is_not_empty = false;
        in.close();

        std::ofstream out(outFile.toStdString(), std::ios::app);
        if (out.is_open())
        {
            if (file_is_not_empty)
                out << "\n";

            out << "PKIStatus : ";
            print_to_file(out, answer);

            out << "PKIFreeText : ";
            print_to_file(out, answer);

            out << "PKIFailureInfo : ";
            print_to_file(out, answer);

            out << "version : ";
            print_to_file(out, answer);

            out << "policy : ";
            print_to_file(out, answer);

            out << "hash alg : ";
            print_to_file(out, answer);

            out << "hash value : ";
            print_to_file(out, answer);

            out << "serial number : ";
            print_to_file(out, answer);

            out << "gen time : ";
            print_to_file(out, answer);

            out << "accuracy seconds : ";
            print_to_file(out, answer);

            out << "accuracy millis : ";
            print_to_file(out, answer);

            out << "accuracy micros : ";
            print_to_file(out, answer);

            out << "ordering : ";
            print_to_file(out, answer);

            out << "nonce : ";
            print_to_file(out, answer);

            out << "tsa : ";
            print_to_file(out, answer);

            out << "extensions : ";
            print_to_file(out, answer);
        }
        out.close();
    }
}
