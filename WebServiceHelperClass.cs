using Config_classes;
using RBClient.Classes.CustomClasses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RBClient.Classes.ServiceClasses
{
    class WebServiceHelperClass<T> where T : System.Web.Services.Protocols.SoapHttpClientProtocol,new()
    {
        public string NAME { get; set; }
        private int ServiceHashCode = 0;
        private T _WebService;
        
        protected ConfigClass Config;

        /// <summary>
        /// Конструктор класса
        /// </summary>
        /// <param name="name"></param>
        /// <param name="config"></param>
        public WebServiceHelperClass(string name, ConfigClass config)
        {
            this.NAME = name;
            this.Config = config;
        }

        /// <summary>
        /// Создаем новый экземпляр сервиса
        /// </summary>
        /// <returns></returns>
        internal T CreateNewService()
        {
            _WebService = CreteService();
            ServiceHashCode = GetServiceHashCode();
            return _WebService;
        }

        private bool ISNOE(string s)
        {
            return String.IsNullOrEmpty(s);
        }
        private bool NISNOE(string s)
        {
            return !String.IsNullOrEmpty(s);
        }


        /// <summary>
        /// Вернуть сервис
        /// </summary>
        /// <returns></returns>
        internal T ReturnService()
        {
            if (_WebService == null || IsConfigChanged(false))
            {
                _WebService = CreateNewService();
            }
            return _WebService;
        }

        /// <summary>
        /// Создаем сервис
        /// </summary>
        /// <returns></returns>
        private T CreteService()
        {
            string _service_url = ServiceUrl();

            if (WebServiceIsDisabled(_service_url))
            {
                return null;
            }

            string _service_name = ServiceUserName();
            string _service_password = ServicePassword();
            string _service_certificate_validation = ServiceCertificateValidation();

            _WebService = new T();

            SetUrl(_WebService, _service_url);

            SetCredentials(_WebService, _service_name, _service_password);

            SetCertificateValidation(_WebService,_service_certificate_validation);

            SetProxy(_WebService);

            return _WebService;
        }

        internal virtual bool WebServiceIsDisabled(string _service_url)
        {
            return false;
        }

        /// <summary>
        /// Устанавливаем валидацию по сертификату
        /// </summary>
        /// <param name="_WebService"></param>
        /// <param name="_service_certificate_validation"></param>
        private void SetCertificateValidation(T _WebService, string _service_certificate_validation)
        {
            if (!CertValidationNeeded(_service_certificate_validation))
            {
                DisableCertificateValidation();
            }
            else
            {
                EnableCertificateValidation();
            }
        }

        /// <summary>
        /// Устанавливаем имя пользователя и пароль сервиса
        /// </summary>
        /// <param name="_WebService"></param>
        /// <param name="_service_name"></param>
        /// <param name="_service_password"></param>
        private void SetCredentials(T _WebService, string _service_name, string _service_password)
        {
            if(NISNOE(_service_name)&&NISNOE(_service_password))
                _WebService.Credentials = new NetworkCredential(ServiceUserName(), ServicePassword());
        }

        /// <summary>
        /// Устанавливаем урл сервиса
        /// </summary>
        /// <param name="_WebService"></param>
        /// <param name="_service_url"></param>
        private void SetUrl(T _WebService, string _service_url)
        {
            if (NISNOE(_service_url))
            {
                _WebService.Url = _service_url;
            }
        }

        #region Свойства сервера

        /// <summary>
        /// Получаем пароль
        /// </summary>
        /// <returns></returns>
        internal virtual string ServicePassword()
        {
            var _var = Config.GetProperty<string>(
                String.Format("{0}_webservice_password", NAME)
                , "");

            var passw = PasswordDecoder.decode_string(_var);
            return passw;
        }

        /// <summary>
        /// Получаем имя пользователя
        /// </summary>
        /// <returns></returns>
        internal virtual string ServiceUserName()
        {
            var _var = Config.GetProperty<string>(
               String.Format("{0}_webservice_login", NAME)
               , "");

            return _var;
        }

        /// <summary>
        /// Флаг валидации сертификата
        /// </summary>
        /// <returns></returns>
        internal virtual string ServiceCertificateValidation()
        {
            var _var = Config.GetProperty<string>(
               String.Format("{0}_webservice_validation_by_сert", NAME)
               , "0");

            return _var;
        }

        /// <summary>
        /// получаем урл
        /// </summary>
        /// <returns></returns>
        internal virtual string ServiceUrl()
        {
            var _var = Config.GetProperty<string>(
              String.Format("{0}_webservice_url", NAME)
              , "");

            return _var;
        }

        #endregion

        #region Свойства прокси

        /// <summary>
        /// Получаем пароль прокси
        /// </summary>
        /// <returns></returns>
        internal virtual string ProxyPassword()
        {
            var _var = Config.GetProperty<string>(
                String.Format("{0}_webservice_proxy_password", NAME)
                , "");

            var passw = PasswordDecoder.decode_string(_var);
            return passw;
        }

        /// <summary>
        /// Получаем имя пользователя прокси
        /// </summary>
        /// <returns></returns>
        internal virtual string ProxyUserName()
        {
            var _var = Config.GetProperty<string>(
               String.Format("{0}_webservice_proxy_login", NAME)
               , "");

            return _var;
        }

        /// <summary>
        /// получаем урл прокси
        /// </summary>
        /// <returns></returns>
        internal virtual string ProxyUrl()
        {
            var _var = Config.GetProperty<string>(
              String.Format("{0}_webservice_proxy_url", NAME)
              , "");

            return _var;
        }

        /// <summary>
        /// получить порт прокси
        /// </summary>
        /// <returns></returns>
        internal virtual int ProxyPort()
        {
            var _var = Config.GetProperty<int>(
              String.Format("{0}_webservice_proxy_port", NAME)
              , -1);
            return _var;
        }

        /// <summary>
        /// Получаем домен прокси
        /// </summary>
        /// <returns></returns>
        internal virtual string ProxyDomain()
        {
            var _var = Config.GetProperty<string>(
              String.Format("{0}_webservice_proxy_domain", NAME)
              , "");

            return _var;
        }

        /// <summary>
        /// Включен ли прокси
        /// </summary>
        /// <returns></returns>
        internal virtual bool ProxyEnabled()
        {
            var _var = Config.GetProperty<bool>(
              String.Format("{0}_webservice_proxy_enabled", NAME)
              , false);

            return _var;
        }
        #endregion

        /// <summary>
        /// Установить прокси
        /// </summary>
        /// <param name="_WebService"></param>
        private void SetProxy(T _WebService)
        {
#if(DEBUG)
            EnableProxy(_WebService);
#else
            bool _proxy_enabled = ProxyEnabled();
            if (_proxy_enabled)
            {
                EnableProxy(_WebService);
            }
            else
            {
                DisableProxy(_WebService);
            }
#endif
        }

        /// <summary>
        /// Выключаем прокси
        /// </summary>
        /// <param name="_WebService"></param>
        private void DisableProxy(T _WebService)
        {
            if (_WebService.Proxy != null)
            {
                _WebService.Proxy = null;
            }
        }

        /// <summary>
        /// Включаем прокси
        /// </summary>
        /// <param name="_WebService"></param>
        private void EnableProxy(T _WebService)
        {
            var proxy = CreateProxy();
            if(proxy!=null)
            {
                _WebService.Proxy = proxy;
            }
        }

        /// <summary>
        /// Создать прокси
        /// </summary>
        /// <returns></returns>
        private IWebProxy CreateProxy()
        {
            string _proxy_url = ProxyUrl();
            int _proxy_port = ProxyPort();
            string _proxy_name = ProxyUserName();
            string _proxy_password = ProxyPassword();
            string _proxy_domain = ProxyDomain();

            WebProxy Proxy = CreateProxy(_proxy_url,_proxy_port);
            SetProxyCredentials(Proxy,_proxy_name, _proxy_password, _proxy_domain);
            return Proxy;
        }

        /// <summary>
        /// Установить данные прокси
        /// </summary>
        /// <param name="Proxy"></param>
        /// <param name="_proxy_name"></param>
        /// <param name="_proxy_password"></param>
        /// <param name="_proxy_domain"></param>
        private void SetProxyCredentials(WebProxy Proxy, string _proxy_name, string _proxy_password, string _proxy_domain)
        {
            if (Proxy != null)
            {
                if (NISNOE(_proxy_name) && NISNOE(_proxy_password))
                {
                    if (NISNOE(_proxy_domain))
                    {
                        Proxy.Credentials = new NetworkCredential(_proxy_name, _proxy_password, _proxy_domain);
                    }
                    else
                    {
                        Proxy.Credentials = new NetworkCredential(_proxy_name, _proxy_password);
                    }
                }
            }
        }

        /// <summary>
        /// Создаем класс прокси
        /// </summary>
        /// <param name="_proxy_url"></param>
        /// <param name="_proxy_port"></param>
        /// <returns></returns>
        private WebProxy CreateProxy(string _proxy_url, int _proxy_port)
        {
            WebProxy wp = null;
            if (NISNOE(_proxy_url))
            {
                if (_proxy_port != -1)
                {
                    wp=new WebProxy(_proxy_url, _proxy_port);
                }
                else
                {
                    new WebProxy(_proxy_url);
                }
            }
            return wp;
        }

        /// <summary>
        /// Включаем встроенную валидацию сертификата
        /// </summary>
        private void EnableCertificateValidation()
        {
            if (ServicePointManager.ServerCertificateValidationCallback != null)
            {
                ServicePointManager.ServerCertificateValidationCallback = null;
            }
        }

        /// <summary>
        /// Выключаем встроенную валидацию сертификата
        /// </summary>
        private void DisableCertificateValidation()
        {
            ServicePointManager.ServerCertificateValidationCallback = null;
            ServicePointManager.ServerCertificateValidationCallback +=
            new RemoteCertificateValidationCallback(CustomCertificateValidatior);
        }

        public static bool CustomCertificateValidatior(object sender,
    X509Certificate certificate, X509Chain chain,
    SslPolicyErrors policyErrors)
        {
            // anything goes!
            return true;

            // PS: you could put your own validation logic here, 
            // through accessing the certificate properties:
            // var publicKey = certificate.GetPublicKey();

        }

        /// <summary>
        /// Условие необходимости валидации
        /// </summary>
        /// <param name="certValidation"></param>
        /// <returns></returns>
        private bool CertValidationNeeded(string certValidation)
        {
            if (certValidation == "1") return true;
            return false;
        }

        /// <summary>
        /// Возвращает хэш конфигурации вебсервиса
        /// </summary>
        /// <returns></returns>
        private int GetServiceHashCode()
        {
            if (!ProxyEnabled())
            {
                return (
                ServiceUrl() +
                ServiceUserName() +
                ServicePassword()).GetHashCode();
            }
            else
            {
                return (
                ServiceUrl() +
                ServiceUserName() +
                ServicePassword() +
                ProxyUrl() +
                ProxyDomain() +
                ProxyPassword() +
                ProxyPort() +
                ProxyUserName() +
                ProxyPassword() +
                ProxyEnabled()
                ).GetHashCode();
            }
        }


        /// <summary>
        /// Изменились ли локальные параметры вебсервиса
        /// </summary>
        /// <returns></returns>
        internal bool IsConfigChanged()
        {
            return !ServiceHashCode.Equals(GetServiceHashCode());
        }

        /// <summary>
        /// Изменился ли конфиг
        /// </summary>
        /// <param name="fullHash">флаг указывает должны ли мы просчитывать весь файл</param>
        /// <returns></returns>
        internal bool IsConfigChanged(bool fullHash)
        {
            if (fullHash)
            {
                return !Config._GetHashCode().Equals(ServiceHashCode);
            }
            else
            {
                return IsConfigChanged();
            }
        }

    }
}
