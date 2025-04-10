-- CreateEnum
CREATE TYPE "Providers" AS ENUM ('GOOGLE', 'YANDEX');

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "Provider" "Providers";
