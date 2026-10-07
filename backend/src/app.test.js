import test from 'node:test';
import assert from 'node:assert/strict';
import {validEmail,validateInquiry} from './app.js';
import {bearerToken} from './supabase.js';

test('email validation accepts normal addresses',()=>{
 assert.equal(validEmail('customer@example.com'),true);
 assert.equal(validEmail(' customer+hydroid@example.co.in '),true);
});

test('email validation rejects malformed addresses',()=>{
 assert.equal(validEmail('customer'),false);
 assert.equal(validEmail('customer@'),false);
 assert.equal(validEmail(''),false);
});

test('bearer token parsing accepts only bearer authorization',()=>{
 assert.equal(bearerToken({headers:{authorization:'Bearer token-value'}}),'token-value');
 assert.equal(bearerToken({headers:{authorization:'Basic token-value'}}),'');
 assert.equal(bearerToken({headers:{}}),'');
});

test('inquiry validation checks required fields and accepts a valid submission',()=>{
 assert.equal(validateInquiry({name:'A',email:'bad',city:''}),'Enter your full name.');
 assert.equal(validateInquiry({name:'Aarav Mehta',contactNumber:'not-a-phone',email:'aarav@example.com',city:'Pune'}),'Enter a valid contact number (4 to 24 digits).');
 assert.equal(validateInquiry({name:'Aarav Mehta',contactNumber:'+91 98765 43210',email:'aarav@example.com',city:'Pune'}),'');
});

test('CORS origin checking permits local development origins and comma-separated FRONTEND_ORIGIN',async()=>{
 const {isOriginAllowed} = await import('./app.js');
 assert.equal(isOriginAllowed(''), true);
 assert.equal(isOriginAllowed('http://127.0.0.1:4174'), true);
 assert.equal(isOriginAllowed('http://localhost:4174'), true);
 assert.equal(isOriginAllowed('http://localhost:5173'), true);

 process.env.FRONTEND_ORIGIN = 'https://www.veids.in,https://veids.in,https://hydroid.vercel.app';
 assert.equal(isOriginAllowed('https://www.veids.in'), true);
 assert.equal(isOriginAllowed('https://veids.in'), true);
 assert.equal(isOriginAllowed('https://hydroid.vercel.app'), true);
 assert.equal(isOriginAllowed('https://malicious-site.com'), false);
});

