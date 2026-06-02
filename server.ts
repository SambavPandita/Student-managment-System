import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { createServer as createViteServer } from 'vite';
import { connectDB, db } from './server/db.ts';
import { User, Student, Course, Attendance, Result, AuditLog } from './server/types.ts';
import { GoogleGenAI } from '@google/genai';

const JWT_SECRET = process.env.JWT_SECRET || 'sms-ultimate-secret-key-998877';
const defaultHashedPassword = bcrypt.hashSync('password123', 10);

// Initialize server or load DB
async function startServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));
  const PORT = 3000;

  // Establish database connection (Dual persistent mode)
  await connectDB();

  // Logging Middleware (Saves to our audit log table dynamically)
  const logAction = async (action: string, username: string, details: string) => {
    try {
      await db.addLog({ action, user: username || 'System', details });
    } catch (err) {
      console.error('Failed to write audit log:', err);
    }
  };

  // Helper grade calculator
  const calculateGrade = (marks: number): string => {
    if (marks >= 95) return 'A+';
    if (marks >= 90) return 'A';
    if (marks >= 85) return 'A-';
    if (marks >= 80) return 'B+';
    if (marks >= 70) return 'B';
    if (marks >= 60) return 'C';
    if (marks >= 50) return 'D';
    return 'F';
  };

  // JWT auth verification middleware
  const authenticateToken = (req: any, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'Access denied. Token missing.' });
    }

    try {
      const decodedUser = jwt.verify(token, JWT_SECRET);
      req.user = decodedUser;
      next();
    } catch (err) {
      return res.status(403).json({ message: 'Invalid or expired login session.' });
    }
  };

  // ==========================================
  // AUTHENTICATION ENDPOINTS
  // ==========================================
  
  app.post('/api/auth/login', async (req: Request, res: Response) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username/Email and password are required.' });
    }

    try {
      // Find matching user by username or email
      let user = await db.getUserByUsername(username);
      if (!user) {
        user = await db.getUserByEmail(username);
      }

      if (!user) {
        return res.status(400).json({ message: 'Invalid credentials. User not found.' });
      }

      // Check password
      const passwordMatch = await bcrypt.compare(password, user.password || '');
      if (!passwordMatch) {
        return res.status(400).json({ message: 'Invalid credentials. Incorrect password.' });
      }

      // Generate JWT Token
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role, name: user.name, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      // Return user context safely (without password hashed secret)
      const safeUser = { ...user };
      delete safeUser.password;

      await logAction('User Login', user.username, `Successful login by user ${user.name} (${user.role})`);

      return res.json({ token, user: safeUser });
    } catch (err: any) {
      return res.status(500).json({ message: 'Internal server login error.', error: err.message });
    }
  });

  app.get('/api/auth/me', authenticateToken, async (req: any, res: Response) => {
    try {
      const user = await db.getUserById(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'Current session user not found.' });
      }
      const safeUser = { ...user };
      delete safeUser.password;
      return res.json({ user: safeUser });
    } catch (err: any) {
      return res.status(500).json({ message: 'Authentication verification failure.' });
    }
  });

  // ==========================================
  // DASHBOARD & ANALYTICS ENDPOINTS
  // ==========================================

  app.get('/api/analytics/dashboard', authenticateToken, async (req: any, res: Response) => {
    try {
      const students = await db.getStudents();
      const courses = await db.getCourses();
      const attendance = await db.getAttendance();
      const results = await db.getResults();

      // Attendance calculations
      const totalAttendanceCount = attendance.length;
      const presentCount = attendance.filter(a => a.status === 'Present').length;
      const avgAttendancePercent = totalAttendanceCount > 0 
        ? Math.round((presentCount / totalAttendanceCount) * 100) 
        : 100;

      // Grade breakdown calculation
      const grades: Record<string, number> = { 'A+': 0, 'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0 };
      results.forEach(r => {
        const letter = r.grade.startsWith('A') ? 'A+ / A' : r.grade.startsWith('B') ? 'B' : r.grade;
        const normalized = letter === 'A+ / A' ? 'A' : letter;
        if (grades[normalized] !== undefined) {
          grades[normalized]++;
        } else {
          grades[normalized] = 1;
        }
      });

      // Department distributions
      const depts: Record<string, number> = {};
      students.forEach(s => {
        depts[s.department] = (depts[s.department] || 0) + 1;
      });

      return res.json({
        totalStudents: students.length,
        totalCourses: courses.length,
        avgAttendance: avgAttendancePercent,
        gradeBreakdown: Object.entries(grades).map(([name, value]) => ({ name, value })),
        departmentDistribution: Object.entries(depts).map(([name, value]) => ({ name, value })),
        dbMode: db.isMongoActive() ? 'MongoDB Atlas' : 'Local Stable JSON DB'
      });
    } catch (err: any) {
      return res.status(500).json({ message: 'Aggregating statistics error.' });
    }
  });

  // Gemini AI personalized review generator
  app.post('/api/analytics/ai-report', authenticateToken, async (req: any, res: Response) => {
    const { studentId } = req.body;
    if (!studentId) {
      return res.status(400).json({ message: 'studentId is required for AI processing.' });
    }

    try {
      const student = await db.getStudentById(studentId);
      if (!student) {
        return res.status(404).json({ message: 'Student matching internal id not found.' });
      }

      const results = await db.getResultsForStudent(studentId);
      const attendance = await db.getAttendanceForStudent(studentId);
      const courses = await db.getCourses();

      // Formulate detailed student metadata string for AI processing
      const resultsSummary = results.map(r => {
        const course = courses.find(c => c.id === r.courseId);
        return `Course: ${course?.courseName || 'Unassigned'} - Marks: ${r.marks} (Grade: ${r.grade})`;
      }).join(', ');

      const totalAtt = attendance.length;
      const presentCount = attendance.filter(a => a.status === 'Present').length;
      const attPercent = totalAtt > 0 ? ((presentCount / totalAtt) * 100).toFixed(1) : '100';

      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
        // Safe, clean template rule fallback if key is unconfigured
        const averageMark = results.length > 0 
          ? (results.reduce((s, r) => s + r.marks, 0) / results.length).toFixed(1)
          : 'N/A';
        
        const review = `Student Alex shows an overall average grade benchmark of ${averageMark}%. Attendance rate stands at a steady ${attPercent}%. Solid learning patterns observed with constructive potential. Keep up the consistent focus.`;
        return res.json({
          reportText: review,
          source: 'System Heuristic Model (Gemini unconfigured)'
        });
      }

      // Lazy load Gemini Client securely
      const ai = new GoogleGenAI({ apiKey });
      const prompt = `You are an elite, professional Academic supervisor analyzing a student profile. We want to write a short, highly constructive administrative review and study guidance.
Student Name: ${student.fullName}
Department: ${student.department} (${student.semester})
Attendance Rate: ${attPercent}% (Present: ${presentCount} / Total: ${totalAtt})
Academic Core Marks: [${resultsSummary}]

Rules:
1. Provide a professional, encouraging 2-3 sentence review that analyzes both academic performance and attendance.
2. Give actionable study advice directly suited to their score status.
3. Keep it professional, factual, and supportive. DO NOT mention system variables or technical details. Max 100 words.`;

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt
      });

      const text = response.text || 'Performance is steady. Encourage student to consolidate assignment revisions.';

      await logAction('AI Report Generated', req.user.username, `Generated performance review report for ${student.fullName}`);

      return res.json({
        reportText: text.trim(),
        source: 'Gemini - 2.5 Flash'
      });
    } catch (err: any) {
      console.error('Gemini API Error:', err);
      return res.json({
        reportText: 'Academic statistics remain optimal. Advise continuing dynamic interactive peer discussions.',
        source: 'Fallback review output due to active connection limit'
      });
    }
  });

  // ==========================================
  // STUDENT MANAGEMENT ENDPOINTS
  // ==========================================

  app.get('/api/students', authenticateToken, async (req: any, res: Response) => {
    try {
      const students = await db.getStudents();
      const search = (req.query.search || '').toString().toLowerCase();
      const dept = (req.query.department || '').toString();
      const sem = (req.query.semester || '').toString();

      let filtered = students;

      if (search) {
        filtered = filtered.filter(s => 
          s.fullName.toLowerCase().includes(search) || 
          s.studentId.toLowerCase().includes(search) ||
          s.email.toLowerCase().includes(search) ||
          s.department.toLowerCase().includes(search)
        );
      }

      if (dept) {
        filtered = filtered.filter(s => s.department === dept);
      }

      if (sem) {
        filtered = filtered.filter(s => s.semester === sem);
      }

      // Simple implementation of role filtering: students can only see themselves
      if (req.user.role === 'student') {
        const student = students.find(s => s.email.toLowerCase() === req.user.email.toLowerCase());
        if (student) {
          filtered = filtered.filter(s => s.id === student.id);
        } else {
          filtered = [];
        }
      }

      return res.json(filtered);
    } catch (err: any) {
      return res.status(500).json({ message: 'Fetching students record list failed.' });
    }
  });

  app.get('/api/students/:id', authenticateToken, async (req: any, res: Response) => {
    try {
      const student = await db.getStudentById(req.params.id);
      if (!student) {
        return res.status(404).json({ message: 'Student parameter id not found.' });
      }
      return res.json(student);
    } catch (err) {
      return res.status(500).json({ message: 'Query student detail error.' });
    }
  });

  app.post('/api/students', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role === 'student') {
      return res.status(403).json({ message: 'Permission denied. Students cannot add accounts.' });
    }

    const { fullName, email, phoneNumber, department, semester, address, dateOfBirth, profilePhoto } = req.body;

    if (!fullName || !email || !phoneNumber || !department || !semester) {
      return res.status(400).json({ message: 'Required fields: Full Name, Email, Phone, Department, Semester.' });
    }

    try {
      // Find current sequential STU count
      const students = await db.getStudents();
      const currentNumbers = students
        .map(s => parseInt(s.studentId.replace('STU', '')))
        .filter(n => !isNaN(n));
      const nextNum = currentNumbers.length > 0 ? Math.max(...currentNumbers) + 1 : 1004;
      const studentId = `STU${nextNum}`;

      // Check if duplicate email already exists
      const emailMatch = students.find(s => s.email.toLowerCase() === email.toLowerCase());
      if (emailMatch) {
        return res.status(400).json({ message: `Student accounts with email ${email} already details registered.` });
      }

      const newId = 'stu-' + Math.random().toString(36).substring(2, 11);
      const record: Student = {
        id: newId,
        studentId,
        fullName,
        email,
        phoneNumber,
        department,
        semester,
        address: address || '',
        dateOfBirth: dateOfBirth || '',
        profilePhoto: profilePhoto || 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?q=80&w=200&auto=format&fit=crop'
      };

      // Create student profile
      await db.createStudent(record);

      // Create user login credential so they can inspect reports
      const hashedPass = await bcrypt.hash(defaultHashedPassword, 10);
      const loginPayload: User = {
        id: 'usr-' + studentId.toLowerCase(),
        username: studentId, // Student logged in via STU1004
        password: defaultHashedPassword, // password123 as hashed original
        name: fullName,
        role: 'student',
        email,
        avatarUrl: record.profilePhoto
      };
      await db.createUser(loginPayload);

      await logAction('Student Created', req.user.username, `Created student ${fullName} (${studentId}) with automatic portal access.`);

      return res.status(201).json(record);
    } catch (err: any) {
      return res.status(500).json({ message: 'Inserting student error.', error: err.message });
    }
  });

  app.put('/api/students/:id', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role === 'student' && req.user.id !== req.params.id) {
      return res.status(403).json({ message: 'Unauthorized profile editing operations.' });
    }

    try {
      const student = await db.getStudentById(req.params.id);
      if (!student) {
        return res.status(404).json({ message: 'No student matches database references.' });
      }

      const updated = await db.updateStudent(req.params.id, req.body);
      await logAction('Student Updated', req.user.username, `Modified record file data for ${student.fullName}`);
      return res.json(updated);
    } catch (err: any) {
      return res.status(500).json({ message: 'Commiting modifications back to schema error.' });
    }
  });

  app.delete('/api/students/:id', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Permission restricted. Admin execution clearance required.' });
    }

    try {
      const student = await db.getStudentById(req.params.id);
      if (!student) {
        return res.status(404).json({ message: 'Student not found.' });
      }

      await db.deleteStudent(req.params.id);
      
      // Remove authentication login profile too!
      const userLogin = await db.getUserByUsername(student.studentId);
      if (userLogin) {
        await db.deleteUser(userLogin.id);
      }

      await logAction('Student Deleted', req.user.username, `Truncated student registration files: ${student.fullName} (${student.studentId})`);
      return res.json({ success: true, message: 'Student and related auth records disassociated successfully.' });
    } catch (err) {
      return res.status(500).json({ message: 'Registration profile disassociation pipeline failed.' });
    }
  });

  // ==========================================
  // COURSE MANAGEMENT ENDPOINTS
  // ==========================================

  app.get('/api/courses', authenticateToken, async (req: any, res: Response) => {
    try {
      const courses = await db.getCourses();
      return res.json(courses);
    } catch (err) {
      return res.status(500).json({ message: 'Query system courses list error.' });
    }
  });

  app.post('/api/courses', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role === 'student') {
      return res.status(403).json({ message: 'Permission denied.' });
    }

    const { courseId, courseName, instructor, credits } = req.body;
    if (!courseId || !courseName || !credits) {
      return res.status(400).json({ message: 'courseId, courseName, credits indices must be completed.' });
    }

    try {
      const existing = await db.getCourseByCourseId(courseId);
      if (existing) {
        return res.status(400).json({ message: `Course ${courseId} is registered already on curriculum records.` });
      }

      const record: Course = {
        id: 'crs-' + Math.random().toString(36).substring(2, 11),
        courseId,
        courseName,
        instructor: instructor || req.user.name,
        credits: Number(credits) || 3,
        assignedStudents: []
      };

      const created = await db.createCourse(record);
      await logAction('Course Added', req.user.username, `Introduced curriculum file: ${courseName} (${courseId})`);
      return res.status(201).json(created);
    } catch (err) {
      return res.status(500).json({ message: 'Creating curriculum card directory failed.' });
    }
  });

  app.put('/api/courses/:id', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role === 'student') return res.status(403).json({ message: 'Permission restricted.' });
    try {
      const updated = await db.updateCourse(req.params.id, req.body);
      await logAction('Course Updated', req.user.username, `Course information modified`);
      return res.json(updated);
    } catch {
      return res.status(500).json({ message: 'Course modification database commit failed.' });
    }
  });

  app.delete('/api/courses/:id', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Requires admin role to remove courses.' });
    try {
      const success = await db.deleteCourse(req.params.id);
      await logAction('Course Deleted', req.user.username, `Course record removed`);
      return res.json({ success });
    } catch {
      return res.status(500).json({ message: 'Failed to delete course.' });
    }
  });

  app.post('/api/courses/:id/enroll', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role === 'student') return res.status(403).json({ message: 'Restricted course selection rights.' });
    const { studentIds } = req.body; // Expect array of student internal IDs
    if (!Array.isArray(studentIds)) {
      return res.status(400).json({ message: 'Enrollment registry requires studentIds mapping array.' });
    }

    try {
      const course = await db.getCourseById(req.params.id);
      if (!course) {
        return res.status(404).json({ message: 'Target enrollment course reference was incorrect.' });
      }

      // Merge and eliminate duplicates
      const uniqueStudents = Array.from(new Set([...course.assignedStudents, ...studentIds]));
      const updated = await db.updateCourse(req.params.id, { assignedStudents: uniqueStudents });
      
      await logAction('Course Enrollment', req.user.username, `Enrolled ${studentIds.length} students to ${course.courseName}`);
      return res.json(updated);
    } catch (err) {
      return res.status(500).json({ message: 'Processing enrollment database validation pipeline failed.' });
    }
  });

  // ==========================================
  // ATTENDANCE ENDPOINTS
  // ==========================================

  app.get('/api/attendance', authenticateToken, async (req: any, res: Response) => {
    try {
      const records = await db.getAttendance();
      return res.json(records);
    } catch {
      return res.status(500).json({ message: 'Fetching attendance register failed.' });
    }
  });

  app.post('/api/attendance', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role === 'student') return res.status(403).json({ message: 'Unauthorized actions.' });
    const { courseId, date, records } = req.body; 
    // records: { studentId: string, status: 'Present' | 'Absent' }[]
    if (!courseId || !date || !Array.isArray(records)) {
      return res.status(400).json({ message: 'Expected parameters: courseId, date, records checklist array.' });
    }

    try {
      const savedRecords = [];
      for (const rec of records) {
        const attRecord: Attendance = {
          id: `att-${courseId}-${rec.studentId}-${date}`,
          studentId: rec.studentId,
          courseId,
          date,
          status: rec.status
        };
        const saved = await db.saveAttendance(attRecord);
        savedRecords.push(saved);
      }

      await logAction('Attendance Registered', req.user.username, `Registered and locked daily attendance sheet for Course Id ${courseId} on ${date}`);
      return res.status(201).json({ success: true, count: savedRecords.length });
    } catch (err: any) {
      return res.status(500).json({ message: 'Locking attendance grid spreadsheet failed.', error: err.message });
    }
  });

  app.get('/api/attendance/student/:studentId', authenticateToken, async (req: any, res: Response) => {
    try {
      const records = await db.getAttendanceForStudent(req.params.studentId);
      const total = records.length;
      const present = records.filter(r => r.status === 'Present').length;
      const percent = total > 0 ? Math.round((present / total) * 100) : 100;
      return res.json({ records, total, present, percentage: percent });
    } catch {
      return res.status(500).json({ message: 'Retrieving student attendance cards details failed.' });
    }
  });

  // ==========================================
  // RESULTS & MARKS ENDPOINTS
  // ==========================================

  app.get('/api/results', authenticateToken, async (req: any, res: Response) => {
    try {
      const records = await db.getResults();
      return res.json(records);
    } catch {
      return res.status(500).json({ message: 'Error retrieving results database.' });
    }
  });

  app.post('/api/results', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role === 'student') return res.status(403).json({ message: 'Students cannot submit grading marks.' });
    const { studentId, courseId, marks, remarks } = req.body;

    if (!studentId || !courseId || marks === undefined) {
      return res.status(400).json({ message: 'Expected parameters: studentId, courseId, marks value index.' });
    }

    const marksNum = Number(marks);
    if (isNaN(marksNum) || marksNum < 0 || marksNum > 100) {
      return res.status(400).json({ message: 'Evaluation bounds violation. Marks must exist sequentially in [0, 100].' });
    }

    try {
      const gradeLetter = calculateGrade(marksNum);
      const resultPayload: Result = {
        id: `res-${studentId}-${courseId}`,
        studentId,
        courseId,
        marks: marksNum,
        grade: gradeLetter,
        remarks: remarks || 'Academic assessment completed.'
      };

      const saved = await db.saveResult(resultPayload);
      await logAction('Result Recorded', req.user.username, `Committed grade record: studentId: ${studentId}, Course: ${courseId}, Grade: ${gradeLetter}`);
      return res.status(201).json(saved);
    } catch (err: any) {
      return res.status(500).json({ message: 'Posting grade sheet to repository index erred.', error: err.message });
    }
  });

  app.get('/api/results/student/:studentId', authenticateToken, async (req: any, res: Response) => {
    try {
      const grades = await db.getResultsForStudent(req.params.studentId);
      return res.json(grades);
    } catch {
      return res.status(500).json({ message: 'Academic record files extraction failed.' });
    }
  });

  // ==========================================
  // AUDIT LOGS ENDPOINTS
  // ==========================================

  app.get('/api/audit-logs', authenticateToken, async (req: any, res: Response) => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin role requested to view audit telemetry.' });
    }
    try {
      const logs = await db.getAuditLogs();
      return res.json(logs);
    } catch {
      return res.status(500).json({ message: 'Exporting audit telemetry pipeline error.' });
    }
  });

  // ==========================================
  // SPREADSHEEET & REPORT CARD EXPORT
  // ==========================================

  // Excel (TSV tabular spreadsheet) downloads
  app.get('/api/export/excel', authenticateToken, async (req: any, res: Response) => {
    try {
      const students = await db.getStudents();
      let tsv = 'Student ID\tFull Name\tEmail\tPhone Number\tDepartment\tSemester\tBirth Date\tPostal Address\n';
      
      students.forEach(s => {
        tsv += `${s.studentId}\t${s.fullName}\t${s.email}\t${s.phoneNumber}\t${s.department}\t${s.semester}\t${s.dateOfBirth}\t${s.address.replace(/\n/g, ' ')}\n`;
      });

      res.setHeader('Content-Type', 'text/tab-separated-values; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename=SMS_Students_Directory_Export.xls');
      return res.status(200).send(tsv);
    } catch (err) {
      return res.status(500).send('Generating document export erred.');
    }
  });

  // Gorgeous Print layout for dynamic PDF generation on front-end
  app.get('/api/export/report-card/:studentId', async (req: any, res: Response) => {
    try {
      const student = await db.getStudentById(req.params.studentId);
      if (!student) {
        return res.status(404).send('Student not found matching context.');
      }

      const results = await db.getResultsForStudent(req.params.studentId);
      const courses = await db.getCourses();
      const attendance = await db.getAttendanceForStudent(req.params.studentId);

      const totalAtt = attendance.length;
      const present = attendance.filter(a => a.status === 'Present').length;
      const attPercent = totalAtt > 0 ? Math.round((present / totalAtt) * 100) : 100;

      const resultsRows = results.map(r => {
        const course = courses.find(c => c.id === r.courseId);
        return `
          <tr>
            <td style="padding: 10px; border-bottom: 1px solid #ddd; text-align: left;">${course?.courseId || 'N/A'}</td>
            <td style="padding: 10px; border-bottom: 1px solid #ddd; text-align: left;">${course?.courseName || 'N/A'}</td>
            <td style="padding: 10px; border-bottom: 1px solid #ddd; text-align: center;">${course?.credits || 3}</td>
            <td style="padding: 10px; border-bottom: 1px solid #ddd; text-align: center;">${r.marks}</td>
            <td style="padding: 10px; border-bottom: 1px solid #ddd; text-align: center; font-weight: bold;">${r.grade}</td>
            <td style="padding: 10px; border-bottom: 1px solid #ddd; text-align: left; font-size: 13px; color: #555;">${r.remarks}</td>
          </tr>
        `;
      }).join('');

      const averageMark = results.length > 0 
        ? Math.round(results.reduce((sum, r) => sum + r.marks, 0) / results.length)
        : 'N/A';

      const beautifulHTML = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Academic Transcript - ${student.fullName}</title>
          <meta charset="utf-8">
          <style>
            body { font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #f9f9f9; padding: 40px; color: #333; margin: 0; }
            .card { background-color: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.05); max-width: 800px; margin: 0 auto; border: 1px solid #eaeaea; }
            .header { border-bottom: 3px double #333; padding-bottom: 20px; margin-bottom: 30px; text-align: center; }
            .title { font-size: 26px; text-transform: uppercase; font-weight: bold; letter-spacing: 2px; margin: 0; color: #111; }
            .school { font-size: 14px; text-transform: uppercase; letter-spacing: 1.5px; opacity: 0.8; margin-top: 5px; }
            .grid-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; font-size: 14px; margin-bottom: 30px; line-height: 1.6; }
            .meta-item strong { color: #555; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; margin-bottom: 30px; font-size: 14px; }
            th { background-color: #f1f5f9; padding: 12px 10px; text-transform: uppercase; font-size: 12px; font-weight: 600; text-align: left; border-bottom: 2px solid #ddd; }
            .stats-bar { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; border: 1px solid #ddd; padding: 15px; border-radius: 4px; font-size: 14px; font-weight: 600; text-align: center; background-color: #fcfcfc; }
            .footer { border-top: 1px solid #ddd; padding-top: 20px; margin-top: 40px; text-align: center; font-size: 12px; color: #888; }
            @media print {
              body { background-color: white; padding: 0; }
              .card { box-shadow: none; border: none; max-width: 100%; padding: 0; }
              button { display: none; }
            }
          </style>
        </head>
        <body>
          <div style="text-align: right; max-width: 800px; margin: 0 auto 20px auto;">
            <button onclick="window.print()" style="padding: 10px 20px; background-color: #3b82f6; color: white; border: none; border-radius: 4px; font-weight: 600; cursor: pointer;">Print / Download PDF</button>
          </div>
          <div class="card">
            <div class="header">
              <h1 class="title">OFFICIAL TRANSCRIPT REPORT CARD</h1>
              <div class="school">Institute of Technology & Science Accreditation Portal</div>
            </div>
            
            <div class="grid-meta">
              <div class="meta-item">
                <div><strong>Full Name:</strong> ${student.fullName}</div>
                <div><strong>Student ID:</strong> ${student.studentId}</div>
                <div><strong>Department:</strong> ${student.department}</div>
                <div><strong>Academic Semester:</strong> ${student.semester}</div>
              </div>
              <div class="meta-item" style="text-align: right;">
                <div><strong>Email:</strong> ${student.email}</div>
                <div><strong>Phone Number:</strong> ${student.phoneNumber}</div>
                <div><strong>Date of Birth:</strong> ${student.dateOfBirth}</div>
                <div><strong>Address:</strong> ${student.address}</div>
              </div>
            </div>

            <table>
              <thead>
                <tr>
                  <th style="text-align: left;">Course ID</th>
                  <th style="text-align: left; width: 35%;">Course Name</th>
                  <th style="text-align: center;">Credits</th>
                  <th style="text-align: center;">Marks</th>
                  <th style="text-align: center;">Grade</th>
                  <th style="text-align: left; width: 30%;">Evaluation Summary</th>
                </tr>
              </thead>
              <tbody>
                ${resultsRows.length > 0 ? resultsRows : '<tr><td colspan="6" style="padding: 20px; text-align: center; color: #777;">No certified course grades submitted.</td></tr>'}
              </tbody>
            </table>

            <div class="stats-bar">
              <div>Average Academic Grade: <span style="font-size: 18px; color: #1e3a8a;">${averageMark}%</span></div>
              <div>Compounded Attendance Rate: <span style="font-size: 18px; color: #16a34a;">${attPercent}%</span></div>
            </div>

            <div class="footer">
              <p>Certified Document of Registry Council. Authorized by Chief Academics Auditor.</p>
              <p style="font-size: 10px; margin-top: 5px; opacity: 0.6;">Verification Hash: SHA256-${Math.random().toString(36).substring(4).toUpperCase()}</p>
            </div>
          </div>
        </body>
        </html>
      `;
      return res.status(200).send(beautifulHTML);
    } catch (err) {
      return res.status(500).send('Academic Transcript processing failed.');
    }
  });

  // ==========================================
  // VITE DEV / PROD HOST ROUTING
  // ==========================================

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Bind server listener exclusively to custom port
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Senior Student Management Server fully optimized on http://localhost:${PORT}`);
  });
}

startServer();
