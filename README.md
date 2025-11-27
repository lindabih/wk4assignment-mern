# wk4assignment-mern
week4 assignment mern
diff --git a/server/package.json b/server/package.json
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/server/package.json
@@ -0,0 +1,38 @@
+{
+  "name": "mern-blog-server",
+  "version": "1.0.0",
+  "main": "server.js",
+  "scripts": {
+    "start": "node server.js",
+    "dev": "nodemon server.js"
+  },
+  "dependencies": {
+    "bcryptjs": "^2.4.3",
+    "cors": "^2.8.5",
+    "dotenv": "^16.0.0",
+    "express": "^4.18.2",
+    "jsonwebtoken": "^9.0.0",
+    "mongoose": "^7.0.0",
+    "multer": "^1.4.5"
+  },
+  "devDependencies": {
+    "nodemon": "^2.0.22"
+  }
+}
+
+diff --git a/server/.env b/server/.env
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/.env
+@@ -0,0 +1,4 @@
+PORT=5000
+MONGO_URI=mongodb://localhost:27017/mern-blog
+JWT_SECRET=change_this_in_prod
+CLIENT_ORIGIN=http://localhost:5173
+
+diff --git a/server/utils/db.js b/server/utils/db.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/utils/db.js
+@@ -0,0 +1,8 @@
+const mongoose = require('mongoose')
+
+async function connectDB(uri) {
+  return mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
+}
+
+module.exports = connectDB
+
+diff --git a/server/models/User.js b/server/models/User.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/models/User.js
+@@ -0,0 +1,17 @@
+const mongoose = require('mongoose')
+
+const UserSchema = new mongoose.Schema({
+  name: { type: String, required: true, trim: true },
+  email: { type: String, required: true, unique: true, lowercase: true },
+  passwordHash: { type: String, required: true },
+}, { timestamps: true })
+
+module.exports = mongoose.model('User', UserSchema)
+
+diff --git a/server/models/Post.js b/server/models/Post.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/models/Post.js
+@@ -0,0 +1,20 @@
+const mongoose = require('mongoose')
+
+const PostSchema = new mongoose.Schema({
+  title: { type: String, required: true },
+  body: { type: String, required: true },
+  imageUrl: { type: String },
+  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
+  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
+}, { timestamps: true })
+
+module.exports = mongoose.model('Post', PostSchema)
+
+diff --git a/server/models/Comment.js b/server/models/Comment.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/models/Comment.js
+@@ -0,0 +1,16 @@
+const mongoose = require('mongoose')
+
+const CommentSchema = new mongoose.Schema({
+  text: { type: String, required: true },
+  authorName: { type: String },
+  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
+  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
+}, { timestamps: true })
+
+module.exports = mongoose.model('Comment', CommentSchema)
+
+diff --git a/server/middleware/authMiddleware.js b/server/middleware/authMiddleware.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/middleware/authMiddleware.js
+@@ -0,0 +1,22 @@
+const jwt = require('jsonwebtoken')
+const User = require('../models/User')
+
+const auth = async (req, res, next) => {
+  try {
+    const header = req.headers.authorization
+    if (!header) return res.status(401).json({ message: 'No token' })
+    const token = header.split(' ')[1]
+    const payload = jwt.verify(token, process.env.JWT_SECRET)
+    req.user = await User.findById(payload.id).select('-passwordHash')
+    if (!req.user) return res.status(401).json({ message: 'Invalid token' })
+    next()
+  } catch (err) {
+    return res.status(401).json({ message: 'Unauthorized', error: err.message })
+  }
+}
+
+module.exports = auth
+
+diff --git a/server/middleware/uploadMiddleware.js b/server/middleware/uploadMiddleware.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/middleware/uploadMiddleware.js
+@@ -0,0 +1,22 @@
+const multer = require('multer')
+const path = require('path')
+const fs = require('fs')
+
+const uploadDir = path.join(__dirname, '..', 'uploads')
+if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir)
+
+const storage = multer.diskStorage({
+  destination: function (req, file, cb) { cb(null, uploadDir) },
+  filename: function (req, file, cb) {
+    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9)
+    cb(null, unique + path.extname(file.originalname))
+  }
+})
+
+const upload = multer({ storage })
+
+module.exports = upload
+
+diff --git a/server/controllers/authController.js b/server/controllers/authController.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/controllers/authController.js
+@@ -0,0 +1,33 @@
+const bcrypt = require('bcryptjs')
+const jwt = require('jsonwebtoken')
+const User = require('../models/User')
+
+exports.register = async (req, res) => {
+  try {
+    const { name, email, password } = req.body
+    if (!email || !password || !name) return res.status(400).json({ message: 'Missing fields' })
+    const exists = await User.findOne({ email })
+    if (exists) return res.status(400).json({ message: 'Email already in use' })
+
+    const passwordHash = await bcrypt.hash(password, 10)
+    const user = await User.create({ name, email, passwordHash })
+    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
+    res.json({ token, user: { id: user._id, name: user.name, email: user.email } })
+  } catch (err) { res.status(500).json({ message: err.message }) }
+}
+
+exports.login = async (req, res) => {
+  try {
+    const { email, password } = req.body
+    const user = await User.findOne({ email })
+    if (!user) return res.status(400).json({ message: 'Invalid credentials' })
+    const match = await bcrypt.compare(password, user.passwordHash)
+    if (!match) return res.status(400).json({ message: 'Invalid credentials' })
+    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
+    res.json({ token, user: { id: user._id, name: user.name, email: user.email } })
+  } catch (err) { res.status(500).json({ message: err.message }) }
+}
+
+diff --git a/server/controllers/postController.js b/server/controllers/postController.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/controllers/postController.js
+@@ -0,0 +1,56 @@
+const Post = require('../models/Post')
+const Comment = require('../models/Comment')
+
+exports.createPost = async (req, res) => {
+  try {
+    const { title, body } = req.body
+    const imageUrl = req.file ? `/uploads/${req.file.filename}` : undefined
+    const post = await Post.create({ title, body, imageUrl, author: req.user._id })
+    res.status(201).json(post)
+  } catch (err) { res.status(500).json({ message: err.message }) }
+}
+
+exports.listPosts = async (req, res) => {
+  try {
+    const { page = 1, limit = 10, q } = req.query
+    const filter = q ? { $or: [{ title: new RegExp(q, 'i') }, { body: new RegExp(q, 'i') }] } : {}
+    const posts = await Post.find(filter)
+      .sort({ createdAt: -1 })
+      .skip((page - 1) * limit)
+      .limit(Number(limit))
+      .populate('author', 'name email')
+    res.json(posts)
+  } catch (err) { res.status(500).json({ message: err.message }) }
+}
+
+exports.getPost = async (req, res) => {
+  try {
+    const post = await Post.findById(req.params.id)
+      .populate('author', 'name email')
+      .populate({ path: 'comments', populate: { path: 'author', select: 'name' } })
+    if (!post) return res.status(404).json({ message: 'Not found' })
+    res.json(post)
+  } catch (err) { res.status(500).json({ message: err.message }) }
+}
+
+exports.updatePost = async (req, res) => {
+  try {
+    const post = await Post.findById(req.params.id)
+    if (!post) return res.status(404).json({ message: 'Not found' })
+    if (!post.author.equals(req.user._id)) return res.status(403).json({ message: 'Forbidden' })
+    const { title, body } = req.body
+    if (req.file) post.imageUrl = `/uploads/${req.file.filename}`
+    if (title) post.title = title
+    if (body) post.body = body
+    await post.save()
+    res.json(post)
+  } catch (err) { res.status(500).json({ message: err.message }) }
+}
+
+exports.deletePost = async (req, res) => {
+  try {
+    const post = await Post.findById(req.params.id)
+    if (!post) return res.status(404).json({ message: 'Not found' })
+    if (!post.author.equals(req.user._id)) return res.status(403).json({ message: 'Forbidden' })
+    await Comment.deleteMany({ post: post._id })
+    await post.remove()
+    res.json({ message: 'Deleted' })
+  } catch (err) { res.status(500).json({ message: err.message }) }
+}
+
+diff --git a/server/controllers/commentController.js b/server/controllers/commentController.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/controllers/commentController.js
+@@ -0,0 +1,20 @@
+const Comment = require('../models/Comment')
+const Post = require('../models/Post')
+
+exports.createComment = async (req, res) => {
+  try {
+    const { text } = req.body
+    if (!text) return res.status(400).json({ message: 'Missing text' })
+    const comment = await Comment.create({
+      text,
+      author: req.user._id,
+      authorName: req.user.name,
+      post: req.params.postId
+    })
+    await Post.findByIdAndUpdate(req.params.postId, { $push: { comments: comment._id } })
+    res.status(201).json(comment)
+  } catch (err) { res.status(500).json({ message: err.message }) }
+}
+
+diff --git a/server/routes/auth.js b/server/routes/auth.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/routes/auth.js
+@@ -0,0 +1,9 @@
+const express = require('express')
+const router = express.Router()
+const { register, login } = require('../controllers/authController')
+
+router.post('/register', register)
+router.post('/login', login)
+
+module.exports = router
+
+diff --git a/server/routes/posts.js b/server/routes/posts.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/routes/posts.js
+@@ -0,0 +1,18 @@
+const express = require('express')
+const router = express.Router()
+const auth = require('../middleware/authMiddleware')
+const upload = require('../middleware/uploadMiddleware')
+const postCtrl = require('../controllers/postController')
+const commentCtrl = require('../controllers/commentController')
+
+router.get('/', postCtrl.listPosts)
+router.post('/', auth, upload.single('image'), postCtrl.createPost)
+router.get('/:id', postCtrl.getPost)
+router.put('/:id', auth, upload.single('image'), postCtrl.updatePost)
+router.delete('/:id', auth, postCtrl.deletePost)
+
+router.post('/:postId/comments', auth, commentCtrl.createComment)
+
+module.exports = router
+
+diff --git a/server/server.js b/server/server.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/server/server.js
+@@ -0,0 +1,38 @@
+require('dotenv').config()
+const express = require('express')
+const cors = require('cors')
+const path = require('path')
+const connectDB = require('./utils/db')
+
+const app = express()
+app.use(express.json())
+app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }))
+
+// static uploads
+app.use('/uploads', express.static(path.join(__dirname, 'uploads')))
+
+// routes
+app.use('/api/auth', require('./routes/auth'))
+app.use('/api/posts', require('./routes/posts'))
+
+app.get('/api/ping', (req, res) => res.json({ ok: true }))
+
+async function start() {
+  try {
+    await connectDB(process.env.MONGO_URI)
+    console.log('Mongo connected')
+    const port = process.env.PORT || 5000
+    app.listen(port, () => console.log('Server running on', port))
+  } catch (err) {
+    console.error(err)
+    process.exit(1)
+  }
+}
+start()
+
+diff --git a/client/package.json b/client/package.json
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/package.json
+@@ -0,0 +1,20 @@
+{
+  "name": "client",
+  "version": "0.0.0",
+  "private": true,
+  "scripts": {
+    "dev": "vite",
+    "build": "vite build",
+    "preview": "vite preview"
+  },
+  "dependencies": {
+    "axios": "^1.4.0",
+    "react": "^18.2.0",
+    "react-dom": "^18.2.0",
+    "react-router-dom": "^6.14.1"
+  },
+  "devDependencies": {
+    "vite": "^5.0.0"
+  }
+}
+
+diff --git a/client/.env b/client/.env
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/.env
+@@ -0,0 +1 @@
+VITE_API_URL=http://localhost:5000/api
+
+diff --git a/client/src/main.jsx b/client/src/main.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/main.jsx
+@@ -0,0 +1,23 @@
+import React from 'react'
+import { createRoot } from 'react-dom/client'
+import { BrowserRouter } from 'react-router-dom'
+import App from './App'
+import './index.css'
+import { AuthProvider } from './context/AuthContext'
+
+createRoot(document.getElementById('root')).render(
+  <React.StrictMode>
+    <AuthProvider>
+      <BrowserRouter>
+        <App />
+      </BrowserRouter>
+    </AuthProvider>
+  </React.StrictMode>
+)
+
+diff --git a/client/src/index.css b/client/src/index.css
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/index.css
+@@ -0,0 +1,6 @@
+/* minimal styles */
+body { font-family: Inter, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; margin: 0 }
+.container { max-width: 900px; margin: 0 auto }
+
+diff --git a/client/src/App.jsx b/client/src/App.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/App.jsx
+@@ -0,0 +1,36 @@
+import React from 'react'
+import { Routes, Route } from 'react-router-dom'
+import Home from './pages/Home'
+import Posts from './pages/Posts'
+import PostDetails from './pages/PostDetails'
+import CreatePost from './pages/CreatePost'
+import Login from './pages/Login'
+import Register from './pages/Register'
+import Navbar from './components/Navbar'
+
+export default function App() {
+  return (
+    <>
+      <Navbar />
+      <div className="container p-4">
+        <Routes>
+          <Route path="/" element={<Home/>} />
+          <Route path="/posts" element={<Posts/>} />
+          <Route path="/posts/:id" element={<PostDetails/>} />
+          <Route path="/create" element={<CreatePost/>} />
+          <Route path="/login" element={<Login/>} />
+          <Route path="/register" element={<Register/>} />
+        </Routes>
+      </div>
+    </>
+  )
+}
+
+diff --git a/client/src/services/api.js b/client/src/services/api.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/services/api.js
+@@ -0,0 +1,16 @@
+import axios from 'axios'
+
+const api = axios.create({
+  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000/api'
+})
+
+export function setToken(token) {
+  if (token) api.defaults.headers.common['Authorization'] = `Bearer ${token}`
+  else delete api.defaults.headers.common['Authorization']
+}
+
+export default api
+
+diff --git a/client/src/services/authService.js b/client/src/services/authService.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/services/authService.js
+@@ -0,0 +1,16 @@
+import api, { setToken } from './api'
+
+export async function login(credentials) {
+  const { data } = await api.post('/auth/login', credentials)
+  if (data.token) setToken(data.token)
+  return data
+}
+
+export async function register(credentials) {
+  const { data } = await api.post('/auth/register', credentials)
+  if (data.token) setToken(data.token)
+  return data
+}
+
+diff --git a/client/src/services/postService.js b/client/src/services/postService.js
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/services/postService.js
+@@ -0,0 +1,12 @@
+import api from './api'
+
+export const listPosts = (params) => api.get('/posts', { params }).then(r => r.data)
+export const getPost = (id) => api.get(`/posts/${id}`).then(r => r.data)
+export const createPost = (formData) => api.post('/posts', formData, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
+export const updatePost = (id, formData) => api.put(`/posts/${id}`, formData, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
+export const deletePost = (id) => api.delete(`/posts/${id}`).then(r => r.data)
+export const createComment = (postId, body) => api.post(`/posts/${postId}/comments`, body).then(r => r.data)
+
+diff --git a/client/src/context/AuthContext.jsx b/client/src/context/AuthContext.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/context/AuthContext.jsx
+@@ -0,0 +1,30 @@
+import React, { createContext, useContext, useEffect, useState } from 'react'
+import { setToken } from '../services/api'
+
+const AuthContext = createContext()
+
+export const AuthProvider = ({ children }) => {
+  const [user, setUser] = useState(() => { try { return JSON.parse(localStorage.getItem('user')) } catch { return null } })
+  const [token, setTokenState] = useState(() => localStorage.getItem('token'))
+
+  useEffect(() => {
+    if (token) { localStorage.setItem('token', token); setToken(token) }
+    else { localStorage.removeItem('token'); setToken() }
+  }, [token])
+
+  useEffect(() => { if (user) localStorage.setItem('user', JSON.stringify(user)); else localStorage.removeItem('user') }, [user])
+
+  return (
+    <AuthContext.Provider value={{ user, setUser, token, setToken: setTokenState }}>
+      {children}
+    </AuthContext.Provider>
+  )
+}
+
+export const useAuth = () => useContext(AuthContext)
+
+diff --git a/client/src/components/Navbar.jsx b/client/src/components/Navbar.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/components/Navbar.jsx
+@@ -0,0 +1,30 @@
+import React from 'react'
+import { Link, useNavigate } from 'react-router-dom'
+import { useAuth } from '../context/AuthContext'
+
+export default function Navbar() {
+  const { user, setUser, setToken } = useAuth()
+  const nav = useNavigate()
+  const logout = () => { setUser(null); setToken(null); nav('/') }
+
+  return (
+    <nav style={{background:'#f3f4f6', padding:12}}>
+      <div className="container" style={{display:'flex', justifyContent:'space-between'}}>
+        <div style={{display:'flex', gap:16}}>
+          <Link to="/">Home</Link>
+          <Link to="/posts">Posts</Link>
+        </div>
+        <div>
+          {user ? (
+            <>
+              <span style={{marginRight:12}}>Hi, {user.name}</span>
+              <button onClick={logout} style={{color:'#c53030'}}>Logout</button>
+            </>
+          ) : (
+            <>
+              <Link to="/login" style={{marginRight:12}}>Login</Link>
+              <Link to="/register">Register</Link>
+            </>
+          )}
+        </div>
+      </div>
+    </nav>
+  )
+}
+
+diff --git a/client/src/pages/Home.jsx b/client/src/pages/Home.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/pages/Home.jsx
+@@ -0,0 +1,12 @@
+import React from 'react'
+import { Link } from 'react-router-dom'
+
+export default function Home(){
+  return (
+    <div>
+      <h1>Welcome to MERN Blog</h1>
+      <p><Link to="/posts">View posts</Link></p>
+    </div>
+  )
+}
+
+diff --git a/client/src/pages/Posts.jsx b/client/src/pages/Posts.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/pages/Posts.jsx
+@@ -0,0 +1,36 @@
+import React, { useEffect, useState } from 'react'
+import { listPosts } from '../services/postService'
+import { Link } from 'react-router-dom'
+
+export default function Posts() {
+  const [posts, setPosts] = useState([])
+  const [q, setQ] = useState('')
+  const [page, setPage] = useState(1)
+
+  useEffect(() => {
+    listPosts({ page, limit: 10, q }).then(setPosts).catch(() => setPosts([]))
+  }, [page, q])
+
+  return (
+    <div>
+      <div style={{display:'flex', gap:8, marginBottom:12}}>
+        <input placeholder="Search..." value={q} onChange={e=>setQ(e.target.value)} style={{flex:1, padding:8}} />
+        <Link to="/create" style={{background:'#2563eb', color:'#fff', padding:'8px 12px', borderRadius:6}}>Create</Link>
+      </div>
+
+      <div style={{display:'grid', gap:12}}>
+        {posts.map(p => (
+          <div key={p._id} style={{border:'1px solid #e5e7eb', padding:12, borderRadius:6}}>
+            <h3 style={{fontWeight:700}}>{p.title}</h3>
+            <p>{p.body?.slice(0,200)}...</p>
+            <Link to={`/posts/${p._id}`} style={{color:'#2563eb'}}>Read more</Link>
+          </div>
+        ))}
+      </div>
+      <div style={{display:'flex', justifyContent:'space-between', marginTop:16}}>
+        <button onClick={() => setPage(p => Math.max(1, p-1))}>Prev</button>
+        <button onClick={() => setPage(p => p+1)}>Next</button>
+      </div>
+    </div>
+  )
+}
+
+diff --git a/client/src/pages/PostDetails.jsx b/client/src/pages/PostDetails.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/pages/PostDetails.jsx
+@@ -0,0 +1,44 @@
+import React, { useEffect, useState } from 'react'
+import { getPost, createComment } from '../services/postService'
+import { useParams } from 'react-router-dom'
+import { useAuth } from '../context/AuthContext'
+
+export default function PostDetails(){
+  const { id } = useParams()
+  const [post, setPost] = useState(null)
+  const [text, setText] = useState('')
+  const { user } = useAuth()
+
+  useEffect(() => { getPost(id).then(setPost).catch(()=>{}) }, [id])
+
+  const onComment = async () => {
+    if (!text) return
+    await createComment(id, { text })
+    const updated = await getPost(id)
+    setPost(updated)
+    setText('')
+  }
+
+  if (!post) return <div>Loading...</div>
+  return (
+    <div>
+      <h1 style={{fontSize:24, fontWeight:700}}>{post.title}</h1>
+      {post.imageUrl && <img src={`http://localhost:5000${post.imageUrl}`} alt="" style={{maxWidth:400, margin:'12px 0'}} />}
+      <p>{post.body}</p>
+      <div style={{marginTop:16}}>
+        <h3>Comments</h3>
+        {post.comments.map(c => (
+          <div key={c._id} style={{border:'1px solid #e5e7eb', padding:8, marginTop:8}}>
+            <strong>{c.authorName || 'Anonymous'}</strong>
+            <p>{c.text}</p>
+          </div>
+        ))}
+      </div>
+      {user ? (
+        <div style={{marginTop:12}}>
+          <textarea value={text} onChange={e=>setText(e.target.value)} style={{width:'100%', padding:8}} />
+          <button onClick={onComment} style={{marginTop:8, background:'#2563eb', color:'#fff', padding:'8px 12px', borderRadius:6}}>Comment</button>
+        </div>
+      ) : <p style={{marginTop:12}}>Please login to comment.</p>}
+    </div>
+  )
+}
+
+diff --git a/client/src/pages/CreatePost.jsx b/client/src/pages/CreatePost.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/pages/CreatePost.jsx
+@@ -0,0 +1,32 @@
+import React, { useState } from 'react'
+import { createPost } from '../services/postService'
+import { useNavigate } from 'react-router-dom'
+
+export default function CreatePost(){
+  const [title, setTitle] = useState('')
+  const [body, setBody] = useState('')
+  const [image, setImage] = useState(null)
+  const nav = useNavigate()
+
+  const submit = async (e) => {
+    e.preventDefault()
+    const fd = new FormData()
+    fd.append('title', title)
+    fd.append('body', body)
+    if (image) fd.append('image', image)
+    const post = await createPost(fd)
+    nav(`/posts/${post._id}`)
+  }
+
+  return (
+    <form onSubmit={submit} style={{maxWidth:640}}>
+      <input value={title} onChange={e=>setTitle(e.target.value)} placeholder="Title" style={{width:'100%', padding:8, marginBottom:8}} />
+      <textarea value={body} onChange={e=>setBody(e.target.value)} placeholder="Body" style={{width:'100%', padding:8, marginBottom:8}} />
+      <input type="file" onChange={e=>setImage(e.target.files[0])} style={{marginBottom:8}} />
+      <button style={{background:'#16a34a', color:'#fff', padding:'8px 12px', borderRadius:6}}>Create</button>
+    </form>
+  )
+}
+
+diff --git a/client/src/pages/Login.jsx b/client/src/pages/Login.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/pages/Login.jsx
+@@ -0,0 +1,32 @@
+import React, { useState } from 'react'
+import { login } from '../services/authService'
+import { useAuth } from '../context/AuthContext'
+import { useNavigate } from 'react-router-dom'
+
+export default function Login(){
+  const [email, setEmail] = useState('')
+  const [password, setPassword] = useState('')
+  const { setUser, setToken } = useAuth()
+  const nav = useNavigate()
+
+  const submit = async (e) => {
+    e.preventDefault()
+    const { token, user } = await login({ email, password })
+    setToken(token)
+    setUser(user)
+    nav('/')
+  }
+
+  return (
+    <form onSubmit={submit} style={{maxWidth:480}}>
+      <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email" style={{width:'100%', padding:8, marginBottom:8}} />
+      <input value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password" type="password" style={{width:'100%', padding:8, marginBottom:8}} />
+      <button style={{background:'#2563eb', color:'#fff', padding:'8px 12px', borderRadius:6}}>Login</button>
+    </form>
+  )
+}
+
+diff --git a/client/src/pages/Register.jsx b/client/src/pages/Register.jsx
+new file mode 100644
+index 0000000..1111111
+--- /dev/null
++++ b/client/src/pages/Register.jsx
+@@ -0,0 +1,36 @@
+import React, { useState } from 'react'
+import { register } from '../services/authService'
+import { useAuth } from '../context/AuthContext'
+import { useNavigate } from 'react-router-dom'
+
+export default function Register(){
+  const [name, setName] = useState('')
+  const [email, setEmail] = useState('')
+  const [password, setPassword] = useState('')
+  const { setUser, setToken } = useAuth()
+  const nav = useNavigate()
+
+  const submit = async (e) => {
+    e.preventDefault()
+    const { token, user } = await register({ name, email, password })
+    setToken(token)
+    setUser(user)
+    nav('/')
+  }
+
+  return (
+    <form onSubmit={submit} style={{maxWidth:480}}>
+      <input value={name} onChange={e=>setName(e.target.value)} placeholder="Name" style={{width:'100%', padding:8, marginBottom:8}} />
+      <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email" style={{width:'100%', padding:8, marginBottom:8}} />
+      <input value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password" type="password" style={{width:'100%', padding:8, marginBottom:8}} />
+      <button style={{background:'#16a34a', color:'#fff', padding:'8px 12px', borderRadius:6}}>Register</button>
+    </form>
+  )
+}
+

