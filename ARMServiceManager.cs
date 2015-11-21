using Config_classes;
using RBClient.Classes.ServiceClasses;
using RBClient.ru.teremok.msk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RBClient.Classes.WebServiceClasses
{
    class ARMServiceManager : WebServiceHelperClass<ARMWeb>
    {
        public ARMServiceManager(ConfigClass config) : base("webservice_1c",config)
        {}

        /// <summary>
        /// Флаг валидации сертификата
        /// </summary>
        /// <returns></returns>
        internal override string ServiceCertificateValidation()
        {
            string address = CParam.GetParam("validation_by_cert");
            return address;
        }

        /// <summary>
        /// получаем урл
        /// </summary>
        /// <returns></returns>
        internal override string ServiceUrl()
        {
            string address = CParam.GetParam("web_service_url");
            return address;
        }

        /// <summary>
        /// Проверяем не выключен ли сервис
        /// </summary>
        /// <param name="_service_url"></param>
        /// <returns></returns>
        internal override bool WebServiceIsDisabled(string _service_url)
        {
            if (_service_url == "null" || _service_url == "off")
            { return true; }
            else { return false; }
        }
    }
}
