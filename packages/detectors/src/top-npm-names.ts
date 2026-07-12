/**
 * Curated list of top-download npm package names — used by the typosquat
 * detector to score name-distance against a corpus of what attackers most
 * commonly target.
 *
 * Sourced from public npm-stat / npmjs.com top-1000 by weekly downloads, then
 * pruned to names that are (a) plausible typosquat targets (short, memorable)
 * and (b) not so generic they'd cause FPs against unrelated new packages.
 *
 * Update procedure: refresh from https://www.npmjs.com/browse/depended once
 * a year; a stale list gradually loses value. See ROADMAP for the automation
 * plan.
 */

export const TOP_NPM_NAMES: readonly string[] = [
  // Very-high-download frameworks & core libs
  '@babel/core', '@babel/parser', '@babel/preset-env', '@babel/runtime',
  '@types/node', '@types/react', '@types/express', '@types/lodash',
  'react', 'react-dom', 'react-native', 'react-router', 'react-router-dom',
  'vue', 'vue-router', 'vuex',
  'angular', '@angular/core', '@angular/common',
  'svelte', 'sveltekit',
  'next', 'nuxt', 'gatsby', 'remix',
  'express', 'koa', 'hapi', 'fastify', 'nestjs', '@nestjs/core',
  // Tooling
  'typescript', 'ts-node', 'tsx', 'esbuild', 'swc', 'webpack', 'rollup', 'vite',
  'babel', 'eslint', 'prettier', 'jest', 'vitest', 'mocha', 'jasmine', 'karma',
  'nodemon', 'pm2', 'husky', 'lint-staged',
  // Utilities
  'lodash', 'lodash-es', 'underscore', 'ramda', 'immer', 'immutable',
  'moment', 'dayjs', 'date-fns', 'luxon',
  'axios', 'node-fetch', 'got', 'request', 'superagent', 'undici',
  'chalk', 'colors', 'ansi-styles', 'strip-ansi', 'picocolors',
  'debug', 'winston', 'pino', 'bunyan', 'log4js',
  'commander', 'yargs', 'minimist', 'meow', 'inquirer', 'prompts', 'ora',
  'glob', 'fast-glob', 'globby', 'chokidar', 'chokidar-cli',
  'fs-extra', 'graceful-fs', 'rimraf', 'mkdirp',
  'semver', 'json5', 'js-yaml', 'toml',
  'uuid', 'nanoid', 'shortid', 'ulid',
  'lru-cache', 'node-cache',
  'jsonwebtoken', 'jwt-decode', 'bcrypt', 'bcryptjs',
  'validator', 'joi', 'ajv', 'zod', 'yup', 'io-ts',
  'dotenv', 'cross-env', 'config',
  // Server / db
  'mongoose', 'mongodb', 'sequelize', 'typeorm', 'prisma', '@prisma/client',
  'pg', 'mysql', 'mysql2', 'sqlite3', 'better-sqlite3', 'redis', 'ioredis',
  'knex', 'drizzle-orm',
  // AWS / cloud
  'aws-sdk', '@aws-sdk/client-s3', '@aws-sdk/client-dynamodb',
  '@google-cloud/storage', '@azure/storage-blob',
  // Templating
  'handlebars', 'ejs', 'pug', 'mustache', 'nunjucks',
  // HTTP / networking
  'ws', 'socket.io', 'socket.io-client', 'http-proxy', 'http-server',
  'cors', 'body-parser', 'multer', 'compression', 'helmet',
  // Frontend styling / building
  'sass', 'less', 'stylus', 'postcss', 'autoprefixer', 'tailwindcss',
  'styled-components', 'emotion', '@emotion/react', '@emotion/styled',
  // Testing / mocking
  'sinon', 'chai', 'should', 'supertest', 'nock', 'msw',
  '@testing-library/react', '@testing-library/dom', '@testing-library/jest-dom',
  'puppeteer', 'playwright', 'cypress',
  // Common polyfills / helpers
  'core-js', 'regenerator-runtime', 'tslib',
  // Auth / passport
  'passport', 'passport-local', 'passport-jwt', 'oauth', 'openid-client',
  // Node-native shims
  'shelljs', 'execa', 'cross-spawn', 'node-notifier',
  // React ecosystem
  'redux', '@reduxjs/toolkit', 'react-redux', 'zustand', 'jotai', 'recoil',
  'react-query', '@tanstack/react-query',
  '@mui/material', '@chakra-ui/react', 'antd',
  'formik', 'react-hook-form',
  // Build tooling supporting
  '@rollup/plugin-node-resolve', '@rollup/plugin-commonjs',
  'rollup-plugin-typescript2',
  // JSON / data
  'jsdom', 'cheerio', 'xml2js', 'fast-xml-parser', 'papaparse',
  // Crypto
  'crypto-js', 'node-forge', 'openssl', 'jsonwebtoken',
  // Query / search
  'querystring', 'query-string', 'qs',
  // Concurrency
  'p-limit', 'p-queue', 'p-map', 'async',
  // Deprecated but still installed frequently — attacker targets
  'request', 'jquery', 'lodash.merge', 'lodash.template',
  // Image / media
  'sharp', 'jimp', 'image-size',
  // Misc heavy hitters
  'through2', 'readable-stream', 'stream-browserify',
  'buffer', 'safe-buffer',
  'process', 'events', 'util',

  // REDTEAM D6 FIX: high-download packages that were absent from the earlier
  // list. These are common typosquat targets — attackers publish `openia`,
  // `nodemaler`, `strippe`, `firebaze` to catch install typos on huge-download
  // packages. Coverage gap identified by the red-team pass.
  //
  // AI/ML SDKs (very high 2024 install growth):
  'openai', '@openai/api', '@anthropic-ai/sdk', 'anthropic',
  'langchain', 'langchainjs', '@langchain/core', '@langchain/openai',
  'ollama', 'llamaindex', 'llama-index', 'huggingface',
  '@huggingface/inference', '@huggingface/transformers',
  'onnxruntime-node', 'transformers.js', 'openaigraph',
  // Payments
  'stripe', '@stripe/stripe-js', '@stripe/react-stripe-js',
  '@stripe/agent-toolkit', 'square', '@squareup/checkout',
  // Comms / auth SaaS
  'discord.js', '@discordjs/rest', '@discordjs/voice', '@discordjs/opus',
  'slack-node', '@slack/web-api', '@slack/bolt', '@slack/rtm-api',
  'telegraf', 'telegram', 'node-telegram-bot-api',
  // Cloud / infra
  'firebase', 'firebase-admin', '@firebase/app', '@firebase/auth',
  '@firebase/firestore', '@firebase/messaging',
  'electron', '@electron/remote', 'electron-builder', 'electron-store',
  'chromedriver', 'geckodriver', 'selenium-webdriver',
  // Error tracking / observability (Sentry ecosystem heavily typosquatted)
  '@sentry/node', '@sentry/react', '@sentry/browser', '@sentry/nextjs',
  '@sentry/vue', '@sentry/angular', '@sentry/electron', '@sentry/tracing',
  '@sentry/utils', '@sentry/types', '@sentry/integrations',
  // NestJS ecosystem
  '@nestjs/core', '@nestjs/common', '@nestjs/platform-express',
  '@nestjs/config', '@nestjs/testing', '@nestjs/typeorm',
  '@nestjs/graphql', '@nestjs/websockets', '@nestjs/mongoose',
  // DevOps / auth secrets
  'dotenv-vault', 'dotenv-safe', 'dotenv-expand', 'dotenv-cli',
  'convict', 'joi', '@sindresorhus/df',
  // Mongo / DBs (dev-only servers often installed for testing)
  'mongodb-memory-server', 'mongodb-client-encryption',
  '@planetscale/database', '@vercel/postgres',
  // Prisma / ORMs beyond top list
  '@prisma/engines', '@prisma/generator-helper', '@prisma/internals',
  'objection', 'bookshelf', 'kysely',
  // Framework companions frequently squat-targeted
  'astro', '@astrojs/react', '@astrojs/tailwind',
  'sveltekit', '@sveltejs/adapter-node', '@sveltejs/adapter-vercel',
  'solid-js', '@solidjs/router', '@solidjs/start',
  // Testing / mocking newer entries
  '@playwright/test', 'playwright-core', '@testing-library/user-event',
  '@storybook/react', '@storybook/testing-library', '@storybook/addon-essentials',
  // Auth libs
  'next-auth', '@auth/core', 'clerk', '@clerk/nextjs', '@clerk/backend',
  'lucia', '@lucia-auth/adapter-prisma',
  // Node build/runtime companions
  'ts-node-dev', 'nodemon-webpack-plugin', 'tsup', 'tsdown', 'unbuild',
  // Redis / queues
  'ioredis', 'bullmq', '@bull-board/api', 'bull',
  // Emails
  'nodemailer', '@sendgrid/mail', 'mailgun.js', 'resend',
  // Popular utility renaming targets
  'ky', 'ofetch', 'redaxios', 'wretch',
];
