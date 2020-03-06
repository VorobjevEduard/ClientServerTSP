#ifndef STATUS_H
#define STATUS_H

#include <QString>

namespace tsp
{

class Status
{
public:
    QString PKIStatus;

    enum PKIStatus
    {
        granted = 0,
        // PKIStatus содержит нулевое значение, TimeStampToken присутствует в ответе
        grantedWithMods = 1,
        // PKIStatus содержит значение, равное единице, в ответе присутствует модифицированное TimeStampToken (отправленный клиенту штамп незначительно отличается от запрашиваемого штампа; ответственность за данные модификации возложена на запрашивающую сторону)
        rejection = 2,
        // отклонение запроса к центру штампов времени
        waiting = 3,
        // обработка запроса не была осуществлена, ожидается повторный запрос
        revocationWarning = 4,
        // это сообщение содержит предупреждение о том, что отзыв сертификата открытого ключа неизбежен
        revocationNotification = 5
        // уведомление о том, что произошел отзыв сертификата
    };

    QString PKIFreeText;

    QString PKIFailureInfo;

    enum PKIFailureInfo
    {
        BadAlg = 0,
        // идентификатор алгоритма хеширования был не распознан или не поддерживается
        BadRequest = 2,
        // запрос запрещен или не поддерживается
        BadDataFormat = 5,
        // представленные данные имеют некорректный формат
        TimeNotAvailable = 14,
        // источник времени TSA недоступен
        UnacceptedPolicy = 15,
        // данный TSA не поддерживает политику, которая была запрошена клиентским приложением
        UnacceptedExtension = 16,
        // расширение, которое было запрошено, не поддерживается
        AddInfoNotAvailable = 17,
        // запрошенная дополнительная информация недоступна
        SystemFailure = 25,
        // произошел сбой системы, поэтому запрос не может быть обработан
        Unknown = -1
    };
};

}

#endif // STATUS_H
