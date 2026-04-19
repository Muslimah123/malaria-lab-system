// server/src/services/emailService.js
let nodemailer;
try { nodemailer = require('nodemailer'); } catch { nodemailer = null; }
const logger = require('../utils/logger');

class EmailService {
  constructor() {
    this._transporter = null;
  }

  get transporter() {
    if (!this._transporter) {
      if (!nodemailer || !process.env.SMTP_HOST || !process.env.SMTP_USER) return null;
      this._transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT) || 587,
        secure: parseInt(process.env.SMTP_PORT) === 465,
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      });
    }
    return this._transporter;
  }

  async send(to, subject, html) {
    if (!this.transporter) {
      logger.debug('Email not sent — SMTP not configured');
      return null;
    }
    try {
      const info = await this.transporter.sendMail({
        from: process.env.EMAIL_FROM || process.env.SMTP_USER,
        to, subject, html
      });
      logger.info(`Email sent to ${to}: ${subject}`);
      return info;
    } catch (err) {
      logger.error('Email send failed:', err.message);
      return null;
    }
  }

  async sendSignOffNotification({ to, patientName, testId, finalStatus, reviewedBy, verificationCode, severity }) {
    const statusColor = finalStatus === 'POSITIVE' ? '#c0392b' : '#1a7a4a';
    const subject = `[Malaria Lab] Result Confirmed — ${testId} — ${finalStatus}`;
    const html = `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
        <div style="background:#1e3a5f;padding:20px;border-radius:8px 8px 0 0">
          <h2 style="color:white;margin:0">Malaria Laboratory Decision Support System</h2>
          <p style="color:#cce0ff;margin:4px 0 0">Diagnosis Confirmed</p>
        </div>
        <div style="background:#f9f9f9;padding:24px;border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px">
          <p>The following test result has been clinically reviewed and confirmed:</p>
          <table style="width:100%;border-collapse:collapse;font-size:14px">
            <tr><td style="padding:8px;color:#555;width:140px">Test ID</td><td style="padding:8px;font-weight:bold;font-family:monospace">${testId}</td></tr>
            <tr style="background:#f0f0f0"><td style="padding:8px;color:#555">Patient</td><td style="padding:8px;font-weight:bold">${patientName}</td></tr>
            <tr><td style="padding:8px;color:#555">Result</td><td style="padding:8px"><span style="background:${statusColor};color:white;padding:3px 10px;border-radius:4px;font-weight:bold">${finalStatus}</span></td></tr>
            ${severity ? `<tr style="background:#f0f0f0"><td style="padding:8px;color:#555">Severity</td><td style="padding:8px;text-transform:capitalize">${severity}</td></tr>` : ''}
            <tr><td style="padding:8px;color:#555">Reviewed By</td><td style="padding:8px">${reviewedBy}</td></tr>
            <tr style="background:#f0f0f0"><td style="padding:8px;color:#555">Verification Code</td><td style="padding:8px;font-family:monospace;font-weight:bold">${verificationCode}</td></tr>
          </table>
          <div style="margin-top:20px;padding:12px;background:#fff3cd;border:1px solid #e6ac00;border-radius:6px;font-size:12px;color:#7d5a00">
            <strong>Important:</strong> This is an AI-assisted decision support result. Clinical judgement must be applied before any treatment decision.
          </div>
        </div>
      </div>`;
    return this.send(to, subject, html);
  }

  async sendFollowUpReminder({ to, patientName, testId, followUpDate, drug }) {
    const subject = `[Malaria Lab] Follow-up Due — ${patientName} (${testId})`;
    const html = `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
        <div style="background:#1e3a5f;padding:20px;border-radius:8px 8px 0 0">
          <h2 style="color:white;margin:0">Follow-up Reminder</h2>
        </div>
        <div style="background:#f9f9f9;padding:24px;border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px">
          <p>A follow-up is due for the following patient:</p>
          <table style="width:100%;border-collapse:collapse;font-size:14px">
            <tr><td style="padding:8px;color:#555;width:140px">Patient</td><td style="padding:8px;font-weight:bold">${patientName}</td></tr>
            <tr style="background:#f0f0f0"><td style="padding:8px;color:#555">Test ID</td><td style="padding:8px;font-family:monospace">${testId}</td></tr>
            <tr><td style="padding:8px;color:#555">Treatment</td><td style="padding:8px">${drug}</td></tr>
            <tr style="background:#f0f0f0"><td style="padding:8px;color:#555">Follow-up Date</td><td style="padding:8px;font-weight:bold">${new Date(followUpDate).toLocaleDateString()}</td></tr>
          </table>
        </div>
      </div>`;
    return this.send(to, subject, html);
  }
}

module.exports = new EmailService();
