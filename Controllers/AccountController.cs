using Google.Authenticator;
using System.Text;
using System.Web.Configuration;
using System.Web.Mvc;
using System.Web.Security;

namespace TwoFactorAuthentication.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(string username, string password)
        {
            if (IsValidUser(username, password))
            {
                //setting auth cookie
                FormsAuthentication.SetAuthCookie(username, false);

                // iki faktörlü kimlik doğrulama kurulum sayfasına yönlendirme
                return RedirectToAction("ShowAuthenticationTokenPage", "Account");
            }
            else
            {
                ViewBag.ErrorMessage = "Invalid username or password";
                return View();
            }
        }

        public ActionResult ShowAuthenticationTokenPage()
        {
            string googleAuthKey = WebConfigurationManager.AppSettings["GoogleAuthKey"];

            //İki Faktörlü Kimlik Doğrulama Kurulumu
            TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();

            var setupInfo = TwoFacAuth.GenerateSetupCode("Shekhartarare.com", "Admin", ConvertSecretToBytes(googleAuthKey, false), 300);

            //"Shekhartarare.com": Vericinin adı.
            //300: Kurulum kodunun geçerli olacağı saniye sayısını temsil eder.

            //qr kod
            ViewBag.BarcodeImageUrl = setupInfo.QrCodeSetupImageUrl;

            ViewBag.SetupCode = setupInfo.ManualEntryKey;
            return View();
        }

        [HttpPost]
        public ActionResult AuthenticateToken()
        {
            var token = Request["EnteredCode"];
            bool isValid = ValidateToken(token);
            if (isValid)
            {
                // Başarılı kimlik doğrulama
                return RedirectToAction("Index", "Home");
            }
            else
            {
                //tekrar giriş sayfasına aktarma
                return RedirectToAction("Logout");
            }
        }

        public bool ValidateToken(string token)
        {
            string googleAuthKey = WebConfigurationManager.AppSettings["GoogleAuthKey"];
            int validationWindow = 1;

            TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();
            return TwoFacAuth.ValidateTwoFactorPIN(googleAuthKey, token, validationWindow);
        }

        private static byte[] ConvertSecretToBytes(string secret, bool secretIsBase32) =>
           secretIsBase32 ? Base32Encoding.ToBytes(secret) : Encoding.UTF8.GetBytes(secret);

        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login");
        }

        private bool IsValidUser(string username, string password)
        {
            //kimlik ve şifreyi doğrulamak için
            return FormsAuthentication.Authenticate(username, password);
        }
    }
}