# Multi-Tenant SaaS Notes Application

A complete multi-tenant SaaS notes application built with Express.js, featuring JWT authentication, role-based access control, subscription management, and a responsive frontend with Tailwind CSS.

## Features

### 🏢 Multi-Tenancy
- **Strict Tenant Isolation**: Each tenant's data is completely isolated using `tenantId` columns
- **Supported Tenants**: Acme Corp and Globex Inc
- **Shared Database Schema**: Efficient resource utilization with secure data separation

### 🔐 Authentication & Authorization
- **JWT-based Authentication**: Secure token-based login system
- **Role-based Access Control**:
  - **Admin**: Can invite users and upgrade subscriptions
  - **Member**: Can only perform CRUD operations on notes
- **Predefined Test Accounts** (password: `password`):
  - `admin@acme.test` (Admin, Acme)
  - `user@acme.test` (Member, Acme)
  - `admin@globex.test` (Admin, Globex)
  - `user@globex.test` (Member, Globex)

### 💳 Subscription Management
- **Free Plan**: Maximum 3 notes per tenant
- **Pro Plan**: Unlimited notes
- **Admin-only Upgrades**: Only admins can upgrade their tenant's subscription

### 📝 Notes Management
- **Full CRUD Operations**: Create, Read, Update, Delete notes
- **Tenant Isolation**: Users can only access notes from their own tenant
- **Role Restrictions**: All operations respect user roles and permissions

### 🎨 Frontend Features
- **Responsive Design**: Built with Tailwind CSS
- **Smooth Animations**: Login form animations, button hover effects, fade transitions
- **Loading States**: Visual feedback during API calls
- **Real-time Updates**: Dynamic UI updates based on subscription status

## Tech Stack

- **Backend**: Express.js with serverless-http for Vercel deployment
- **Database**: SQLite with in-memory storage (easily replaceable with persistent DB)
- **Authentication**: JWT (JSON Web Tokens)
- **Frontend**: Vanilla JavaScript with Tailwind CSS
- **Deployment**: Vercel with serverless functions

## Project Structure