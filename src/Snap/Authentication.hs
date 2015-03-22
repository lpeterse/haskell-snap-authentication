{-# LANGUAGE OverloadedStrings #-}
module Snap.Authentication where

import Data.Monoid
import Control.Monad
import Control.Exception
import Control.Monad.IO.Class
import Control.Applicative

import Snap.Core
import LDAP
import Web.Cookie

import Data.Maybe
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base16.Lazy as BL16
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

data Credentials
   = Credentials
     { dn       :: T.Text
     , password :: T.Text
     }

instance Aeson.FromJSON Credentials where
    parseJSON (Aeson.Object v) = Credentials
                              <$> v Aeson..: "user"
                              <*> v Aeson..: "pass"
    parseJSON _                = mzero

authenticate :: (MonadSnap m) => LDAP -> m Credentials
authenticate ldap = do
  -- Expect the body to be no longer than 1k to avoid denial of service.
  body  <- readRequestBody 1024
  creds <- case Aeson.decode body of
             Nothing    -> reject400
             Just creds -> return creds
  authorized <- liftIO $ ( do
               ldapSimpleBind ldap (T.unpack $ dn creds) (T.unpack $ password creds)
               return True
           ) `catch` ( \(SomeException e)-> do
               print e
               return False
           )
  if not authorized then do
    modifyResponse (setHeader "Set-Cookie" $ "authorization=; path=/; HttpOnly; secure;")
    reject401
  else do
    modifyResponse (setHeader "Set-Cookie" $ "authorization=" <> B16.encode (BL.toStrict body) <> "; path=/; HttpOnly; secure;")
    return creds

getCredentials :: (MonadSnap m) => m Credentials
getCredentials = do
  auth  <-  fromMaybe ""
        <$> lookup "authorization"
        <$> parseCookies
        <$> fromMaybe ""
        <$> getHeader "Cookie"
        <$> getRequest
  case Aeson.decode $ fst $ BL16.decode $ BL.fromStrict auth of
    Nothing -> do
      reject401
    Just creds -> do
      return creds

reject400 :: (MonadSnap m) => m a
reject400 = do
      modifyResponse $ setResponseStatus 400 "Bad Request"
      getResponse >>= finishWith
      pass

reject401 :: (MonadSnap m) => m a
reject401 = do
      modifyResponse $ setResponseStatus 401 "Unauthorized"
      getResponse >>= finishWith
      pass