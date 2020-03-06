#include <QString>

#include "response.h"

namespace tsp
{
    Response::Response()
    {
        version = "1";
        policy = "";
        m_i = new message_imprint {"", ""};
        serialNumber = "";
        genTime = "";
        mAccuracy = new accuracy {0, 0, 0};
        ordering = "";
        nonce = "";
        tsa = "";
        extensions = "";
    }

    Response::Response(QString version, QString policy, QString hash_alg, QString hashed_msg,
                       QString serialNumber, QString genTime, int seconds, int millis, int micros,
                       QString ordering, QString nonce, QString tsa, QString extensions)
    {
        m_i = new message_imprint
        {
                hash_alg,
                hashed_msg
        };
        this->policy = policy;
        this->serialNumber = serialNumber;
        this->genTime = genTime;
        mAccuracy = new accuracy
        {
                seconds,
                millis,
                micros
        };
        this->ordering = ordering;
        this->nonce = nonce;
        this->tsa = tsa;
        this->extensions = extensions;
    }

    Response::Response(const Response& t)
    {
        m_i = new message_imprint
        {
            t.m_i->hash_algorithm,
            t.m_i->hashed_message
        };
        this->policy = t.policy;
        this->serialNumber = t.serialNumber;
        this->genTime = t.genTime;
        mAccuracy = new accuracy
        {
                t.mAccuracy->seconds,
                t.mAccuracy->millis,
                t.mAccuracy->micros
        };
        this->ordering = t.ordering;
        this->nonce = t.nonce;
        this->tsa = t.tsa;
        this->extensions = t.extensions;
    }

    Response::~Response()
    {
        delete m_i;
    }

    Response& Response::operator=(const Response& t)
    {
        if (&t == this) return *this;
        delete m_i;
        m_i = new message_imprint {
            t.m_i->hash_algorithm,
            t.m_i->hashed_message
        };
        this->policy = t.policy;
        this->serialNumber = t.serialNumber;
        this->genTime = t.genTime;
        mAccuracy = new accuracy
        {
                t.mAccuracy->seconds,
                t.mAccuracy->millis,
                t.mAccuracy->micros
        };
        this->ordering = t.ordering;
        this->nonce = t.nonce;
        this->tsa = t.tsa;
        this->extensions = t.extensions;
        return *this;
    }

    QString Response::get_version() const
    {
        return version;
    }

    QString Response::get_policy() const
    {
        return policy;
    }

    QString Response::get_hash_algorithm() const
    {
        return m_i->hash_algorithm;
    }

    QString Response::get_hashed_message() const
    {
        return m_i->hashed_message;
    }

    QString Response::get_serial_number() const
    {
        return serialNumber;
    }

    QString Response::get_gen_time() const
    {
        return genTime;
    }

    int Response::get_seconds() const
    {
        return mAccuracy->seconds;
    }

    int Response::get_millis() const
    {
        return mAccuracy->millis;
    }

    int Response::get_micros() const
    {
        return mAccuracy->micros;
    }

    QString Response::get_ordering() const
    {
        return ordering;
    }

    QString Response::get_nonce() const
    {
        return nonce;
    }

    QString Response::get_tsa() const
    {
        return tsa;
    }

    QString Response::get_extensions() const
    {
        return extensions;
    }
}
