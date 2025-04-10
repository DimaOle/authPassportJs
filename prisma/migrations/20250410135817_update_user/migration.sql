/*
  Warnings:

  - You are about to drop the column `Provider` on the `users` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "users" DROP COLUMN "Provider",
ADD COLUMN     "provider" "Providers";
