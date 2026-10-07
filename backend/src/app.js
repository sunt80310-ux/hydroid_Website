import 'dotenv/config';
import express from 'express';
import {bearerToken,createPublicSupabaseClient} from './supabase.js';
import { appendInquiryToSheet } from './googleSheets.js';

const app=express();
const fail=(res,status,error)=>res.status(status).json({error});
const authAttempts=new Map();
const inquiryAttempts=new Map();

const allowedOrigins = new Set([
 'http://127.0.0.1:4174',
 'http://localhost:4174',
 'http://localhost:5173',
 'http://127.0.0.1:5173'
]);

export function isOriginAllowed(origin){
 if(!origin)return true;
 if(process.env.FRONTEND_ORIGIN){
  const origins=process.env.FRONTEND_ORIGIN.split(',').map(s=>s.trim());
  if(origins.includes(origin))return true;
 }
 return allowedOrigins.has(origin);
}

app.disable('x-powered-by');
app.use(express.json({limit:'32kb'}));
app.use((req,res,next)=>{
 const origin=req.headers.origin;
 if(origin&&isOriginAllowed(origin)){
  res.setHeader('Access-Control-Allow-Origin',origin);
  res.setHeader('Vary','Origin');
  res.setHeader('Access-Control-Allow-Headers','Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');
 }
 res.setHeader('X-Content-Type-Options','nosniff');
 res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
 if(req.method==='OPTIONS')return res.sendStatus(isOriginAllowed(origin)?204:403);
 next();
});

function trustedOrigin(req,res,next){
 const origin=req.headers.origin;
 if(origin&&!isOriginAllowed(origin))return fail(res,403,'Request origin is not allowed.');
 next();
}

function authRateLimit(req,res,next){
 const key=req.ip||req.socket.remoteAddress||'unknown';
 const now=Date.now();
 const current=authAttempts.get(key);
 if(current&&current.until>now&&current.count>=12)return fail(res,429,'Too many authentication attempts. Try again later.');
 if(!current||current.until<=now)authAttempts.set(key,{count:1,until:now+15*60*1000});
 else current.count+=1;
 next();
}

function inquiryRateLimit(req,res,next){
 const key=req.ip||req.socket.remoteAddress||'unknown';
 const now=Date.now();
 const current=inquiryAttempts.get(key);
 if(current&&current.until>now&&current.count>=5)return fail(res,429,'Too many submissions. Please try again later.');
 if(!current||current.until<=now)inquiryAttempts.set(key,{count:1,until:now+60*60*1000});
 else current.count+=1;
 next();
}

export function validEmail(value){
 return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value||'').trim());
}

export function validateInquiry({name='',contactNumber='',email='',city=''}){
 if(name.length<2||name.length>80)return 'Enter your full name.';
 if(contactNumber&&!/^[+()\d\s.-]{4,24}$/.test(contactNumber))return 'Enter a valid contact number (4 to 24 digits).';
 if(!validEmail(email)||email.length>254)return 'Enter a valid email address (e.g., name@example.com).';
 if(city.length<2||city.length>80)return 'Enter your city.';
 return '';
}

async function optionalUser(req,_res,next){
 try{
  const token=bearerToken(req);
  if(!token)return next();
  const {data:{user},error}=await createPublicSupabaseClient(token).auth.getUser(token);
  if(!error&&user)req.user={id:user.id,email:user.email,name:user.user_metadata?.full_name||user.user_metadata?.name||'',role:'customer'};
  next();
 }catch(error){next(error)}
}

app.get('/api/health',(_req,res)=>res.json({ok:true,service:'hydroid-auth'}));

app.post('/api/inquiries',trustedOrigin,inquiryRateLimit,async(req,res,next)=>{try{
 const name=String(req.body?.name||'').trim();
 const contactNumber=String(req.body?.contactNumber||'').trim();
 const email=String(req.body?.email||'').trim().toLowerCase();
 const city=String(req.body?.city||'').trim();
 const company=String(req.body?.company||'').trim();
 if(company)return res.status(201).json({ok:true});
 const validationError=validateInquiry({name,contactNumber,email,city});
 if(validationError)return fail(res,400,validationError);
 try {
  await appendInquiryToSheet({ name, contactNumber, email, city });
 } catch (sheetError) {
  console.error('Google Sheets append failed:', sheetError.message);
  return fail(res, 503, 'The form is temporarily unavailable. Please try again shortly.');
 }
 res.status(201).json({ok:true});
}catch(error){next(error)}});

app.post('/api/auth/signup',trustedOrigin,authRateLimit,async(req,res,next)=>{try{
 const name=String(req.body?.name||'').trim();
 const email=String(req.body?.email||'').trim().toLowerCase();
 const password=String(req.body?.password||'');
 if(name.length<2||name.length>80)return fail(res,400,'Enter your name (at least 2 characters).');
 if(!validEmail(email))return fail(res,400,'Enter a valid email address.');
 if(password.length<8||password.length>128)return fail(res,400,'Password must contain 8 to 128 characters.');
 const redirectOrigin=req.headers.origin||process.env.FRONTEND_ORIGIN||'http://127.0.0.1:4174';
 const options={data:{full_name:name,name},emailRedirectTo:`${redirectOrigin}/#home`};
 const {data,error}=await createPublicSupabaseClient().auth.signUp({email,password,options});
 if(error)return fail(res,error.status||400,error.message);
 res.status(201).json({
  user:data.user,
  session:data.session,
  message:data.session?'Account created successfully.':'Check your email to confirm your account, then sign in.'
 });
}catch(error){next(error)}});

app.post('/api/auth/login',trustedOrigin,authRateLimit,async(req,res,next)=>{try{
 const email=String(req.body?.email||'').trim().toLowerCase();
 const password=String(req.body?.password||'');
 if(!validEmail(email)||!password)return fail(res,400,'Enter your email and password.');
 const {data,error}=await createPublicSupabaseClient().auth.signInWithPassword({email,password});
 if(error)return fail(res,error.status||401,error.message);
 authAttempts.delete(req.ip||req.socket.remoteAddress||'unknown');
 res.json({user:data.user,session:data.session,message:'Signed in successfully.'});
}catch(error){next(error)}});

app.post('/api/auth/logout',async(req,res,next)=>{try{
 const token=bearerToken(req);
 if(token){
  const client=createPublicSupabaseClient(token);
  await client.auth.signOut().catch(()=>{});
 }
 res.json({ok:true,message:'Signed out successfully.'});
}catch(error){next(error)}});

app.get('/api/auth/me',optionalUser,(req,res)=>res.json({user:req.user||null}));

app.use((error,_req,res,_next)=>{
 console.error(error);
 fail(res,500,process.env.NODE_ENV==='development'?error.message:'Server error.');
});

export default app;
