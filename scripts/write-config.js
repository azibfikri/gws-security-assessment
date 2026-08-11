#!/usr/bin/env node
/** Writes public config.js for Vercel (anon key only — never a service role). */
const fs = require("fs");
const path = require("path");

const defaultBase = "https://dgkundohraqgdvctjonq.supabase.co/functions/v1/gws-audit-api";
const defaultAnon =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRna3VuZG9ocmFxZ2R2Y3Rqb25xIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODY0MzQ0OTgsImV4cCI6MjEwMjAxMDQ5OH0.PTJ9U0WIL2ZQYkb9-O00liPsm_aymAuJoFJn4s161hI";

const apiBase = (process.env.GWS_AUDIT_API_BASE || defaultBase).replace(/\/+$/, "");
const anonKey = process.env.GWS_SUPABASE_ANON_KEY || defaultAnon;

const out = `window.GWS_AUDIT = {
  apiBase: ${JSON.stringify(apiBase)},
  anonKey: ${JSON.stringify(anonKey)}
};
`;

fs.writeFileSync(path.join(__dirname, "..", "config.js"), out, "utf8");
console.log("write-config: wrote config.js");
