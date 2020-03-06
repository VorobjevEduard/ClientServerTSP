#ifndef RESPONSE_H
#define RESPONSE_H

#include <QString>

namespace  tsp
{

class Response
{
public:
    Response();

    Response(QString version, QString policy = "", QString hash_alg = "", QString hashed_msg = "",
             QString serialNumber = "", QString genTime = "", int seconds = 0, int millis = 0, int micros = 0,
             QString ordering = "", QString nonce = "", QString tsa = "", QString extensions = "");

    Response(const Response& t);

    ~Response();

    Response& operator=(const Response& t);

    QString get_version() const;

    QString get_policy() const;

    QString get_hash_algorithm() const;

    QString get_hashed_message() const;

    QString get_serial_number() const;

    QString get_gen_time() const;

    int get_seconds() const;

    int get_millis() const;

    int get_micros() const;

    QString get_ordering() const;

    QString get_nonce() const;

    QString get_tsa() const;

    QString get_extensions() const;

private:
    struct message_imprint
    {
        QString hash_algorithm;
        QString hashed_message;
    };

    struct accuracy
    {
      int seconds;
      int millis;
      int micros;
    };

    QString version;
    QString policy;
    message_imprint* m_i;
    QString serialNumber;
    QString genTime;
    accuracy* mAccuracy;
    QString ordering;
    QString nonce;
    QString tsa;
    QString extensions;

};

}

#endif // RESPONSE_H
