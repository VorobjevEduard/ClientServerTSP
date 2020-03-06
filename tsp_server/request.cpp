#include <QString>

#include "request.h"

namespace tsp
{
    Request::Request()
    {
        tsr = new time_stamp_request{ "1", "", "" };
        req_policy = "";
        nonce = "";
        cert_req = "";
        extensions = "";
    }

    Request::Request(QString v, QString hash_alg, QString hashed_msg,
        QString req_policy, QString nonce, QString cert_req, QString extensions)
    {
        tsr = new time_stamp_request{ v, hash_alg, hashed_msg};
        this->req_policy = req_policy;
        this->nonce = nonce;
        this->cert_req = cert_req;
        this->extensions = extensions;
    }

    Request::Request(const Request& t)
    {
        tsr = new time_stamp_request {
            t.tsr->version,
            t.tsr->msg_imprint.hash_algorithm,
            t.tsr->msg_imprint.hashed_message
        };
        this->req_policy = t.req_policy;
        this->nonce = t.nonce;
        this->cert_req = t.cert_req;
        this->extensions = t.extensions;
    }

    Request::~Request()
    {
        delete tsr;
    }

    Request& Request::operator=(const Request& t)
    {
        if (&t == this) return *this;
        delete tsr;
        tsr = new time_stamp_request {
            t.tsr->version,
            t.tsr->msg_imprint.hash_algorithm,
            t.tsr->msg_imprint.hashed_message
        };
        this->req_policy = t.req_policy;
        this->nonce = t.nonce;
        this->cert_req = t.cert_req;
        this->extensions = t.extensions;
        return *this;
    }

    QString Request::get_version() const
    {
        return tsr->version;
    }

    QString Request::get_hash_algorithm() const
    {
        return (tsr->msg_imprint).hash_algorithm;
    }

    QString Request::get_hashed_message() const
    {
        return (tsr->msg_imprint).hashed_message;
    }

    QString Request::get_req_policy() const
    {
        return req_policy;
    }

    QString Request::get_nonce() const
    {
        return nonce;
    }

    QString Request::get_cert_req() const
    {
        return cert_req;
    }

    QString Request::get_extensions() const
    {
        return extensions;
    }
}
