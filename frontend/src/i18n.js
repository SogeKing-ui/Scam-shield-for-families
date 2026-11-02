// Interface languages for the app shell and the account screens (sign in, sign up, forgot/reset password,
// email confirmation). The checker and Family screens are still English only.
//
// The Spanish and Haitian Creole text should be reviewed by native speakers before real users see it.
import { createContext, useContext } from 'react'

export const LANGS = [
  { code: 'en', label: 'English' },
  { code: 'es', label: 'Español' },
  { code: 'ht', label: 'Kreyòl ayisyen' },
]

export const LangContext = createContext('en')

const S = {
  tagline: {
    en: 'Paste a strange text or email and find out if it looks like a scam, and why.',
    es: 'Pega un mensaje o correo raro y averigua si parece una estafa, y por qué.',
    ht: 'Kole yon tèks oswa yon imèl ki sanble pa nòmal, epi konnen si li sanble yon awnak, ak poukisa.',
  },
  language: { en: 'Language', es: 'Idioma', ht: 'Lang' },
  tabCheck: { en: 'Check a message', es: 'Revisar un mensaje', ht: 'Tcheke yon mesaj' },
  tabFamily: { en: 'Family', es: 'Familia', ht: 'Fanmi' },
  newCount: { en: '({n} new)', es: '({n} nuevos)', ht: '({n} nouvo)' },
  tabSignIn: { en: 'Sign in', es: 'Iniciar sesión', ht: 'Konekte' },
  signOut: { en: 'Sign out ({name})', es: 'Cerrar sesión ({name})', ht: 'Dekonekte ({name})' },
  footer: {
    en: 'Scam Shield looks for common warning signs. It can be wrong. When in doubt, ask someone you trust.',
    es: 'Scam Shield busca señales de alerta comunes. Puede equivocarse. Si tienes dudas, pregunta a alguien de confianza.',
    ht: 'Scam Shield ap chèche siy avètisman komen. Li ka fè erè. Lè w gen dout, mande yon moun ou fè konfyans.',
  },

  titleLogin: { en: 'Sign in', es: 'Iniciar sesión', ht: 'Konekte' },
  titleSignup: { en: 'Create an account', es: 'Crear una cuenta', ht: 'Kreye yon kont' },
  titleForgot: { en: 'Forgot your password?', es: '¿Olvidaste tu contraseña?', ht: 'Ou bliye modpas ou?' },
  titleReset: { en: 'Choose a new password', es: 'Elige una contraseña nueva', ht: 'Chwazi yon nouvo modpas' },
  leadLogin: {
    en: 'Sign in to send messages to your family helper, or to see what your family has sent you.',
    es: 'Inicia sesión para enviar mensajes a tu ayudante familiar o para ver lo que tu familia te envió.',
    ht: 'Konekte pou voye mesaj bay moun fanmi ki ap ede w la, oswa pou wè sa fanmi w voye ba ou.',
  },
  leadSignup: {
    en: 'An account lets a person and a trusted family member work together. Checking a message never needs one.',
    es: 'Una cuenta permite que una persona y un familiar de confianza trabajen juntos. Revisar un mensaje nunca la necesita.',
    ht: 'Yon kont pèmèt yon moun ak yon manm fanmi li fè konfyans travay ansanm. Pou tcheke yon mesaj, ou pa bezwen kont.',
  },
  leadForgot: {
    en: 'Enter your email and we will send you a link to choose a new one.',
    es: 'Escribe tu correo y te enviaremos un enlace para elegir una contraseña nueva.',
    ht: 'Antre imèl ou epi n ap voye yon lyen ba ou pou w chwazi yon nouvo modpas.',
  },
  leadReset: {
    en: 'Pick a new password for your account. You will be signed out on other devices.',
    es: 'Elige una contraseña nueva para tu cuenta. Se cerrará tu sesión en otros dispositivos.',
    ht: 'Chwazi yon nouvo modpas pou kont ou. W ap dekonekte sou lòt aparèy yo.',
  },
  yourName: { en: 'Your name', es: 'Tu nombre', ht: 'Non ou' },
  iAm: { en: 'I am…', es: 'Yo soy…', ht: 'Mwen se…' },
  roleProtected: {
    en: 'someone who wants help staying safe from scams',
    es: 'alguien que quiere ayuda para protegerse de las estafas',
    ht: 'yon moun ki vle èd pou rete an sekirite devan awnak',
  },
  roleHelper: {
    en: 'a family member or friend who helps someone',
    es: 'un familiar o amigo que ayuda a alguien',
    ht: 'yon manm fanmi oswa yon zanmi ki ap ede yon moun',
  },
  email: { en: 'Email', es: 'Correo electrónico', ht: 'Imèl' },
  password: { en: 'Password', es: 'Contraseña', ht: 'Modpas' },
  newPassword: { en: 'New password', es: 'Contraseña nueva', ht: 'Nouvo modpas' },
  again: { en: 'Type it again', es: 'Escríbela otra vez', ht: 'Ekri l ankò' },
  hint: {
    en: 'Use at least 10 characters. A few random words works well.',
    es: 'Usa al menos 10 caracteres. Unas cuantas palabras al azar funcionan bien.',
    ht: 'Itilize omwen 10 karaktè. Kèk mo o aza mache byen.',
  },
  btnLogin: { en: 'Sign in', es: 'Iniciar sesión', ht: 'Konekte' },
  btnSignup: { en: 'Create account', es: 'Crear cuenta', ht: 'Kreye kont' },
  btnForgot: { en: 'Send me a link', es: 'Enviarme un enlace', ht: 'Voye yon lyen ban mwen' },
  btnReset: { en: 'Change my password', es: 'Cambiar mi contraseña', ht: 'Chanje modpas mwen' },
  wait: { en: 'Please wait…', es: 'Espera un momento…', ht: 'Tanpri tann…' },
  forgotLink: { en: 'Forgot your password?', es: '¿Olvidaste tu contraseña?', ht: 'Ou bliye modpas ou?' },
  newHere: { en: 'New here? ', es: '¿Primera vez? ', ht: 'Premye fwa ou isit la? ' },
  haveAccount: { en: 'Already have an account? ', es: '¿Ya tienes una cuenta? ', ht: 'Ou gen yon kont deja? ' },
  back: { en: 'Back to sign in', es: 'Volver a iniciar sesión', ht: 'Tounen nan koneksyon' },
  forgotSent: {
    en: 'If that email has an account, we sent a link to choose a new password. It works for 30 minutes.',
    es: 'Si ese correo tiene una cuenta, enviamos un enlace para elegir una contraseña nueva. Funciona durante 30 minutos.',
    ht: 'Si imèl sa a gen yon kont, nou voye yon lyen pou chwazi yon nouvo modpas. Li mache pandan 30 minit.',
  },
  changed: {
    en: 'Your password was changed. Please sign in with the new one.',
    es: 'Tu contraseña fue cambiada. Inicia sesión con la nueva.',
    ht: 'Modpas ou chanje. Tanpri konekte ak nouvo a.',
  },
  mismatch: { en: 'The two passwords are not the same.', es: 'Las dos contraseñas no son iguales.', ht: 'De modpas yo pa menm.' },

  confirmNeed: {
    en: 'Please confirm your email address. We sent a link to {email}.',
    es: 'Confirma tu correo electrónico. Enviamos un enlace a {email}.',
    ht: 'Tanpri konfime adrès imèl ou. Nou voye yon lyen bay {email}.',
  },
  resend: { en: 'Send it again', es: 'Enviarlo de nuevo', ht: 'Voye l ankò' },
  resent: {
    en: 'We sent a new link. Check your email.',
    es: 'Enviamos un enlace nuevo. Revisa tu correo.',
    ht: 'Nou voye yon nouvo lyen. Gade imèl ou.',
  },
  verified: { en: 'Your email is confirmed. Thank you!', es: 'Tu correo está confirmado. ¡Gracias!', ht: 'Imèl ou konfime. Mèsi!' },
}

// Messages the server sends in English, shown in the chosen language.
const SERVER = {
  'Email or password is incorrect.': {
    es: 'El correo o la contraseña no es correcto.',
    ht: 'Imèl la oswa modpas la pa kòrèk.',
  },
  'Too many failed attempts. Please try again in 15 minutes.': {
    es: 'Demasiados intentos fallidos. Inténtalo de nuevo en 15 minutos.',
    ht: 'Twòp tantativ ki echwe. Tanpri eseye ankò nan 15 minit.',
  },
  'Too many requests. Please wait a moment and try again.': {
    es: 'Demasiadas solicitudes. Espera un momento e inténtalo de nuevo.',
    ht: 'Twòp demann. Tanpri tann yon ti moman epi eseye ankò.',
  },
  'Please enter a valid email address.': {
    es: 'Escribe un correo electrónico válido.',
    ht: 'Tanpri antre yon adrès imèl ki valid.',
  },
  'Please enter a name (1 to 60 characters).': {
    es: 'Escribe un nombre (de 1 a 60 caracteres).',
    ht: 'Tanpri antre yon non (1 a 60 karaktè).',
  },
  'Please choose a role.': { es: 'Elige una opción.', ht: 'Tanpri chwazi yon wòl.' },
  'Use a password with 10 to 128 characters.': {
    es: 'Usa una contraseña de 10 a 128 caracteres.',
    ht: 'Itilize yon modpas ki gen 10 a 128 karaktè.',
  },
  'The password cannot be your email.': {
    es: 'La contraseña no puede ser tu correo.',
    ht: 'Modpas la pa ka menm ak imèl ou.',
  },
  'The password cannot be your email. Please ask for a new link.': {
    es: 'La contraseña no puede ser tu correo. Pide un enlace nuevo.',
    ht: 'Modpas la pa ka menm ak imèl ou. Tanpri mande yon nouvo lyen.',
  },
  'Could not create that account. Try a different email, or sign in.': {
    es: 'No se pudo crear esa cuenta. Prueba con otro correo o inicia sesión.',
    ht: 'Nou pa t kapab kreye kont sa a. Eseye yon lòt imèl, oswa konekte.',
  },
  'This link has expired or was already used. Please ask for a new one.': {
    es: 'Este enlace caducó o ya se usó. Pide uno nuevo.',
    ht: 'Lyen sa a ekspire oswa yo deja itilize l. Tanpri mande yon lòt.',
  },
  'This link has expired or was already used. Sign in and ask for a new one.': {
    es: 'Este enlace caducó o ya se usó. Inicia sesión y pide uno nuevo.',
    ht: 'Lyen sa a ekspire oswa yo deja itilize l. Konekte epi mande yon lòt.',
  },
  'Please sign in.': { es: 'Inicia sesión.', ht: 'Tanpri konekte.' },
  'Request not allowed.': { es: 'Solicitud no permitida.', ht: 'Demann sa a pa pèmèt.' },
  'Cannot reach the checker. Is the server running?': {
    es: 'No se puede conectar con el verificador. ¿Está funcionando el servidor?',
    ht: 'Pa ka rantre an kontak ak verifikatè a. Èske sèvè a ap mache?',
  },
  'Please confirm your email first. We sent you a link when you signed up.': {
    es: 'Primero confirma tu correo. Te enviamos un enlace cuando te registraste.',
    ht: 'Konfime imèl ou anvan. Nou te voye yon lyen lè w te enskri.',
  },
}

export function translate(key, lang, vars = {}) {
  const entry = S[key]
  let text = (entry && (entry[lang] || entry.en)) || key
  for (const [k, v] of Object.entries(vars)) text = text.split(`{${k}}`).join(String(v))
  return text
}

export function translateError(message, lang) {
  return SERVER[message]?.[lang] || message
}

export function useLang() {
  return useContext(LangContext)
}

export function useT() {
  const lang = useContext(LangContext)
  return (key, vars) => translate(key, lang, vars)
}

export function detectLang() {
  try {
    const saved = window.localStorage.getItem('ss_lang')
    if (LANGS.some((l) => l.code === saved)) return saved
  } catch { /* storage can be blocked */ }
  const nav = (navigator.language || 'en').toLowerCase()
  if (nav.startsWith('es')) return 'es'
  if (nav.startsWith('ht')) return 'ht'
  return 'en'
}

export function rememberLang(code) {
  try { window.localStorage.setItem('ss_lang', code) } catch { /* ignore */ }
  document.documentElement.lang = code
}
